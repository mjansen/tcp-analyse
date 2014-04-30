{-# LANGUAGE PackageImports    #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE TupleSections     #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric     #-}

module PreprocessPcap
  ( TCPConnection(..)
  , TCPPacket(..)
  , getStreams
  , getStreamsN
  , getNext
  , showLine
  , connectionFileName
  , normalisedConnection
  ) where

import Data.Word
import Data.List (sort)
import Data.Maybe
import Data.Either
import Data.Time

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Network.Pcap

import Data.Set (Set)
import qualified Data.Set as Set

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

import Foreign.Store

import GHC.Generics
import Data.Serialize
import Data.Ethernet
import "network-data" Data.IP
import Data.CSum
import Data.TCP

import Data.Traversable (Traversable)
import qualified Data.Traversable as Trav
import Data.Foldable (Foldable)
import qualified Data.Foldable as Fold

import qualified Data.Vector as V
import qualified Data.Vector.Mutable as VM

import Control.Monad
import Data.Array.IArray
import Data.Array.MArray
import Data.Array.IO

import Text.Printf

import TCPOptions

data TCPConnection = TCPConnection
  { srcAddr       :: !IPv4
  , dstAddr       :: !IPv4
  , srcPort       :: !TCPPort
  , dstPort       :: !TCPPort
  } deriving (Eq, Ord, Generic) --, Show)

instance Serialize TCPConnection

instance Show TCPConnection where
  show (TCPConnection sa da sp dp) = printf "%s:%5d -> %s:%5d" (showA sa) (unwrap sp) (showA da) (unwrap dp)
    where showA :: IPv4 -> String
          showA (IPv4 x) = printf "%d.%d.%d.%d" (x `quot` 2^24) ((x `quot` 2^16) `rem` 2^8) ((x `quot` 2^8) `rem` 2^8) (x `rem` 2^8)
          unwrap (TCPPort x) = x

connectionFileName (TCPConnection sa da sp dp) = printf "%s.%d-%s.%d" (showA sa) (unwrap sp) (showA da) (unwrap dp)
    where showA :: IPv4 -> String
          showA (IPv4 x) = printf "%d.%d.%d.%d" (x `quot` 2^24) ((x `quot` 2^16) `rem` 2^8) ((x `quot` 2^8) `rem` 2^8) (x `rem` 2^8)
          unwrap (TCPPort x) = x

normalisedConnection (TCPConnection sa da sp dp) = min (TCPConnection sa da sp dp) (TCPConnection da sa dp sp)

data TCPPacket = TCPPacket
  { tUseconds     :: {-# UNPACK #-} !Word64
  , seqNumber     :: {-# UNPACK #-} !Word64 -- SeqNumber
  , ackNumber     :: {-# UNPACK #-} !Word64 -- AckNumber
  , dataOffset    :: {-# UNPACK #-} !Int
  , res           :: {-# UNPACK #-} !Int
  , flags         :: {-# UNPACK #-} !Int    -- fromEnum (_ :: [TCPFlag])
  , windowSize    :: {-# UNPACK #-} !Int
  , urgentPtr     :: {-# UNPACK #-} !Int
  , len           :: {-# UNPACK #-} !Int
  , tcpOptions    ::                !TCPOptions
  } deriving (Eq, Ord, Show, Read, Generic) -- , Data, Typeable)

instance Serialize TCPPacket

getList :: PcapHandle -> IO [(PktHdr, ByteString)]
getList h = do
  x <- nextBS h
  case (hdrCaptureLength . fst $ x) of
    0 -> return []
    _ -> fmap (x:) . getList $ h
    
getListV :: PcapHandle -> IO [V.Vector (PktHdr, ByteString)]
getListV h = do
  v <- V.replicateM 1000 (nextBS h)
  case (hdrCaptureLength . fst . V.last $ v) of
    0 -> return [v]
    _ -> fmap (v:) . getListV $ h
    
data Headers = Headers
  { eH :: !EthernetHeader
  , iH :: !IPv4Header
  , tH :: !TCPHeader
  , tO :: !TCPOptions
  } deriving (Show, Eq, Ord, Read, Generic)
             
instance Serialize Headers where
  put _ = return ()
  get = do
    eh <- get :: Get EthernetHeader
    ih <- get :: Get IPv4Header  -- does this get the options as well?
    case protocol ih of
      6 -> do th@(TCPHdr _ _ _ _ offset _ _ _ _ _) <- get :: Get TCPHeader
              to <- isolate ((offset - 5) * 4) get :: Get TCPOptions
              return $ Headers eh ih th to
      x -> fail $ "protocol " ++ show x

mkTCPPacket :: PktHdr -> IPv4Header -> TCPHeader -> TCPOptions -> (TCPConnection, TCPPacket)
mkTCPPacket (PktHdr  t1 t2 _ l)
            (IPv4Hdr hl _ _ tl _ _ _ _ _ _ sa da)
            (TCPHdr  sp dp (SN s) (AN a) d r f w _ u)
            options
            = ( TCPConnection sa da sp dp
              , TCPPacket (fromInteger $ toInteger t1 * 1000000 + toInteger t2)
                          (fromInteger . toInteger $ s)
                          (fromInteger . toInteger $ a)
                          d r (fromEnum f) w u
                          (tl - hl*4 - d*4)  -- total length less ip header length less tcp header length
                          options
              )

uplift :: (a, b) -> (a, [b])
uplift (x, y) = (x, [y])

mkTCPPacket' :: PktHdr -> ByteString -> Maybe (TCPConnection, TCPPacket)
mkTCPPacket' ph str =
  case decode str of
    Right (Headers _ ih th tO) -> Just $ mkTCPPacket ph ih th tO
    Left msg          -> Nothing

getStreams :: PcapHandle -> IO (Map TCPConnection [TCPPacket])
getStreams handle = do
  rs <- getList handle
  -- rs <- readStore (Store 0) :: IO [(PktHdr, ByteString)]
  let xs = map uplift . catMaybes . map (uncurry mkTCPPacket') $ rs
      combine []  b = b
      combine [a] b = a:b
  return $ Map.fromListWith combine xs

getStreams' :: PcapHandle -> IO (Map TCPConnection [TCPPacket], VM.IOVector (PktHdr, ByteString))
getStreams' handle = do
  rs <- getListV handle
  let tform v = V.foldr' (\x db -> Map.insertWith (+) (fmap fst . uncurry mkTCPPacket' $ x) 1 db) Map.empty v
  let db1 = Map.unionsWith (+) (map tform rs)
      dbSize = Map.size db1
      db2 = Map.fromList . zip (Map.keys db1) $ [0..]
      totalSize = Map.foldr (+) 0 db1
  print db1
  vv <- VM.new totalSize
  print $ VM.length vv
  let rs0 = head rs
  let blockAction offset vb = mapM_ (\i -> VM.write vv i (vb V.! i)) [offset .. offset + (V.length vb) - 1]
  mapM_ (uncurry blockAction) (zip [0..] rs)
  return (Map.empty, vv)
{-  
loopy = do
  v <- (newListArray (0, 99) []) :: IO(IOArray Int Int)
  return v

let xs = map uplift . catMaybes . map (uncurry mkTCPPacket') $ rs
      combine []  b = b
      combine [a] b = a:b
  return $ Map.fromListWith combine xs
-}

data Structure = Structure (Map TCPConnection Int)                              -- find index of connection
                           (IOArray Int Int)                                    -- how many packets for each connection (using index)
                           (IOArray Int (TCPConnection, IOArray Int TCPPacket)) -- Array of packets

getStreamsNew :: PcapHandle -> Structure -> IO Structure
getStreamsNew h db@(Structure idx pktCount packets) = do
  (hdr, str) <- nextBS h
  case hdrCaptureLength hdr of
    0 -> do
           let s = Map.size idx
           pktCount' <- mapIndices (0, s - 1) id pktCount
           packets'  <- mapIndices (0, s - 1) id $ packets
           x <- getElems pktCount'
           y <- getElems packets'
           y' <- mapM (\(sz, (c, a)) -> fmap (c,) (mapIndices (0, sz - 1) id a)) $ zip x y
           packets'' <- newListArray (0, s - 1) y'
           return $ Structure idx pktCount' packets''
    _ -> case mkTCPPacket' hdr str of
      Just (c, p) -> case Map.lookup c idx of
        Just i  -> do j <- readArray pktCount i
                      writeArray pktCount i (j + 1)
                      when (j == 1000) (do
                        (c', a) <- readArray packets i
                        a' <- newListArray (0, 999999) <=< getElems $ a
                        writeArray packets i (c', a'))
                      (c', a) <- readArray packets i
                      writeArray a j p
                      getStreamsNew h (Structure idx pktCount packets)
        Nothing -> do let n = Map.size idx
                      writeArray pktCount n 1
                      a <- newListArray (0, 999) []
                      writeArray a 0 p
                      writeArray packets n (c, a)
                      getStreamsNew h (Structure (Map.insert c n idx) pktCount packets)
      Nothing -> getStreamsNew h db

instance Ord PktHdr where
  compare (PktHdr a0 b0 c0 d0) (PktHdr a1 b1 c1 d1) = compare (a0, b0, c0, d0) (a1, b1, c1, d1)

emptyStructure :: IO Structure
emptyStructure = do
  pktCounts <- newListArray (0,9999) []
  packets   <- newListArray (0,9999) []
  return $ Structure (Map.empty) pktCounts packets

getStreamsN :: PcapHandle -> IO (Map TCPConnection (Array Int TCPPacket))
getStreamsN h = do
  es <- emptyStructure
  Structure a b c <- getStreamsNew h es
  xs <- getElems c
  let (cs, as) = unzip xs
  as' <- mapM freeze as -- :: IO [Array Int TCPPacket]
  return $ Map.fromList . zip cs $ as'

{--}

getNext :: PcapHandle -> IO (Maybe ((PktHdr, ByteString), Maybe (TCPConnection, TCPPacket)))
getNext h = do
  (hdr, str) <- nextBS h
  case hdrCaptureLength hdr of
    0 -> return Nothing
    _ -> let x = mkTCPPacket' hdr str in seq x (return $ Just ((hdr, str), x))

showLine :: Maybe (TCPConnection, TCPPacket) -> String
showLine Nothing = "?"
showLine (Just (TCPConnection sa da sp dp, TCPPacket tU sn an off res fl ws up len tO)) =
  printf "%02d:%02d:%02d.%06d IP %s.%d > %s.%d: Flags [.], %sack %d, win %d, options [%s], length %d"
         ((hour + 10) `rem` 24) minute second usecond
         (showA sa) (unwrap sp) (showA da) (unwrap dp)
         (if len == 0 then "" else printf "seq %d:%d, " sn ((fromEnum sn + len) `rem` 2^32))
         an ws
         (showOptionsLike tO)
         len
  where showA :: IPv4 -> String
        showA (IPv4 x) = printf "%d.%d.%d.%d" (x `quot` 2^24) ((x `quot` 2^16) `rem` 2^8) ((x `quot` 2^8) `rem` 2^8) (x `rem` 2^8)
        unwrap (TCPPort x) = x
        hour    = (tU `quot` (1000000*60*60)) `rem` 24
        minute  = (tU `quot` (1000000*60)   ) `rem` 60
        second  = (tU `quot`  1000000       ) `rem` 60
        usecond =  tU `rem`   1000000

{-

12:18:14.870449 IP 65.51.211.2.50966 > 10.255.200.7.16078: Flags [.], ack 369054803, win 12291, options [nop,nop,TS val 2083534154 ecr

instance Show TCPConnection where
  show (TCPConnection sa da sp dp) = printf "%s:%5d -> %s:%5d" (showA sa) (unwrap sp) (showA da) (unwrap dp)
    where showA :: IPv4 -> String
          showA (IPv4 x) = printf "%d.%d.%d.%d" (x `quot` 2^24) ((x `quot` 2^16) `rem` 2^8) ((x `quot` 2^8) `rem` 2^8) (x `rem` 2^8)
          unwrap (TCPPort x) = x

data TCPPacket = TCPPacket
  { tUseconds     :: {-# UNPACK #-} !Word64
  , seqNumber     :: {-# UNPACK #-} !Word64 -- SeqNumber
  , ackNumber     :: {-# UNPACK #-} !Word64 -- AckNumber
  , dataOffset    :: {-# UNPACK #-} !Int
  , res           :: {-# UNPACK #-} !Int
  , flags         :: {-# UNPACK #-} !Int    -- fromEnum (_ :: [TCPFlag])
  , windowSize    :: {-# UNPACK #-} !Int
  , urgentPtr     :: {-# UNPACK #-} !Int
  , len           :: {-# UNPACK #-} !Int
  , tcpOptions    ::                !TCPOptions
  } deriving (Eq, Ord, Show, Read, Generic) -- , Data, Typeable)

-}

{--}

-- duration in uSeconds:
    
duration :: Array Int TCPPacket -> Integer
duration xa =
  let (a, b) = bounds xa
      tMin = tUseconds $ xa ! a
      tMax = tUseconds $ xa ! b
  in toInteger $ tMax - tMin
     
startTime :: Array Int TCPPacket -> UTCTime
startTime xa =
  let (a, b) = bounds xa
      tMin = tUseconds $ xa ! a
      epoch = UTCTime (fromGregorian 1970 1 1) 0
  in (`addUTCTime` epoch) . fromInteger . toInteger $ tMin

endTime :: Array Int TCPPacket -> UTCTime
endTime xa =
  let (a, b) = bounds xa
      tMax = tUseconds $ xa ! b
      epoch = UTCTime (fromGregorian 1970 1 1) 0
  in (`addUTCTime` epoch) . fromInteger . toInteger $ tMax

volume :: Array Int TCPPacket -> Integer
volume xa =
  let (a, b) = bounds xa
      tMin = PreprocessPcap.seqNumber $ xa ! a
      tMax = PreprocessPcap.seqNumber $ xa ! b
  in case compare tMin tMax of
    LT -> toInteger $ tMax - tMin
    EQ -> 0
    GT -> toInteger $ (toInteger tMax + 2^32 - toInteger tMin)
  
speed :: Array Int TCPPacket -> Integer
speed xa = (1000000 * volume xa) `quot` duration xa

lastPacket :: Array Int TCPPacket -> TCPPacket
lastPacket xa =
  let (_, b) = bounds xa
  in xa ! b

lastFlags :: Array Int TCPPacket -> [TCPFlag]
lastFlags = toEnum . PreprocessPcap.flags . lastPacket

readDB :: String -> IO (Either String (Map TCPConnection (Array Int TCPPacket)))
readDB = fmap decode . B.readFile

newtype ConnectionDuration = ConnectionDuration Integer
                           deriving (Eq, Ord, Read, Generic)

instance Show ConnectionDuration where
  show (ConnectionDuration x) = printf "%6.1f" ((fromInteger :: Integer -> Double) x / 1000000.0)

data TCPStats = TCPStats
  { s_duration  :: ConnectionDuration
  , s_speed     :: Integer
  , s_volume    :: Integer
  , s_lastFlags :: [TCPFlag]
  , s_startTime :: UTCTime
  , s_endTime   :: UTCTime
  } deriving (Eq, Ord, Show, Read, Generic)

stats :: Array Int TCPPacket -> TCPStats
stats xa = TCPStats (ConnectionDuration . duration $ xa) (speed xa) (volume xa) (lastFlags xa) (startTime xa) (endTime xa)
