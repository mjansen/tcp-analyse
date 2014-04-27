import System.Environment
import Network.Pcap
import PreprocessPcap

import Control.Applicative

import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

import Data.Set (Set)
import qualified Data.Set as Set

import Text.Printf

import Data.Serialize

type ConnectionDB = Map TCPConnection [(PktHdr, ByteString)]

main = do
  fNames <- getArgs
  case fNames of
    [] -> return ()
    (fName:_) -> do
      globalHeader <- L.toStrict . L.take (4*6) <$> L.readFile fName
      let loop s [] = return ()
          loop s (name:rest) = do
            s' <- process globalHeader s name
            loop s' rest
      loop Set.empty fNames

process :: ByteString -> Set String -> String -> IO (Set String)
process globalHeader filesWritten fName = do
  let db :: ConnectionDB
      db = Map.empty
  h <- openOffline fName
  let loop h db  = do
        r <- getNext h
        case r of
          Nothing -> return db
          Just ((h0, s0), Just (c, (TCPPacket _ _ _ _ _ _ _ _ l _))) -> do
            let trimmedLength = min (hdrCaptureLength h0) (hdrWireLength h0 - toEnum l)
            loop h (addPacket (normalisedConnection c) (h0 { hdrCaptureLength = trimmedLength }, B.take (fromEnum trimmedLength) s0) db)
          Just (x, Nothing) -> do
            loop h db
  db' <- loop h db
  print $ Map.size db'
  flushSessions globalHeader filesWritten db'

addPacket :: TCPConnection
          -> (PktHdr, ByteString)
          -> Map TCPConnection [(PktHdr, ByteString)]
          -> Map TCPConnection [(PktHdr, ByteString)]
addPacket c x db =
  case Map.lookup c db of
    Nothing -> Map.insert c (x:[]) db
    Just xs -> Map.insert c (x:xs) db

-- write the individual connections out in separate pcap files.

flushSessions :: ByteString -> Set String -> Map TCPConnection [(PktHdr, ByteString)] -> IO (Set String)
flushSessions globalHeader filesWritten = (fmap Set.unions) . mapM (uncurry $ flushSession globalHeader filesWritten) . Map.toList

flushSession :: ByteString -> Set String -> TCPConnection -> [(PktHdr, ByteString)] -> IO (Set String)
flushSession globalHeader filesWritten c xs' = do
  let xs = reverse xs'
      fName = connectionFileName c
  printf "%s: %d\n" (show c) (length xs)
  if fName `Set.member` filesWritten
    then do B.appendFile fName . B.concat . map (uncurry flushPacket) $ xs
            return filesWritten
    else do B.writeFile fName . B.concat . (globalHeader:) . map (uncurry flushPacket) $ xs
            return $ Set.insert fName filesWritten

flushPacket :: PktHdr -> ByteString -> ByteString
flushPacket h s =
  let hstr = encode h
  in B.append hstr s

-- Since there is no good pcap library function to write out a pcap file, we do our own serialization.

instance Serialize PktHdr where
  get = do
    seconds       <- getWord32host
    microSeconds  <- getWord32host
    captureLength <- getWord32host
    wireLength    <- getWord32host
    return $ PktHdr seconds microSeconds captureLength wireLength

  put (PktHdr seconds microSeconds captureLength wireLength) = do
    putWord32host seconds
    putWord32host microSeconds
    putWord32host captureLength
    putWord32host wireLength

-- end
