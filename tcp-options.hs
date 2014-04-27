{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleInstances #-}

import GHC.Generics
import Data.Serialize
import Data.Word

import Data.ByteString.Char8 (ByteString, pack, unpack)

data TCPOptions = TCPOptions [TCPOption]
                deriving (Eq, Ord, Show, Read, Generic)

tcpOptionEND    =  0
tcpOptionNOP    =  1
tcpOptionMSS    =  2
tcpOptionWS     =  3
tcpOptionSackOK =  4
tcpOptionSack   =  5
tcpOptionTS     =  8
tcpOptionACR    = 14
tcpOptionACD    = 15

getOptions :: Get TCPOptions
getOptions = do
  optionKind <- getWord8
  case fromEnum optionKind of
    x | x == tcpOptionEND    -> return $ TCPOptions []
      | x == tcpOptionNOP    -> getOptions
      | x == tcpOptionTS     -> getOptionTS   >>= getMoreOptions
      | x == tcpOptionSack   -> getOptionSack >>= getMoreOptions
      | x == tcpOptionACD    -> getWord8 >>= skip . (+ (-2)) . fromEnum  >> getOptions
      | x == tcpOptionMSS    -> getWord8 >> getWord16be   >> getOptions
      | x == tcpOptionWS     -> getWord8 >> getWord8      >> getOptions
      | x == tcpOptionSackOK -> getWord8 >> getOptions
      | x == tcpOptionACR    -> getWord8 >> getWord8      >> getOptions
      | otherwise            -> getOptions

getMoreOptions :: TCPOption -> Get TCPOptions
getMoreOptions o = fmap (\(TCPOptions xs) -> TCPOptions (o:xs)) getOptions

getOptionTS :: Get TCPOption
getOptionTS = do
  optionLength <- fmap fromEnum $ getWord8
  myTS <- getWord32be
  yrTS <- getWord32be
  return $ OptionTS myTS yrTS

getSackPair = do
  bStart <- getWord32be
  bEnd   <- getWord32be
  return (bStart, bEnd)

getOptionSack :: Get TCPOption
getOptionSack = do
  optionLength <- fmap fromEnum $ getWord8
  case optionLength of
    x | x == 10 -> do
      (b0, b1) <- getSackPair
      return $ OptionSack1 b0 b1
      | x == 18 -> do
      (b0, b1) <- getSackPair
      (c0, c1) <- getSackPair
      return $ OptionSack2 b0 b1 c0 c1
      | x == 26 -> do
      (b0, b1) <- getSackPair
      (c0, c1) <- getSackPair
      (d0, d1) <- getSackPair
      return $ OptionSack3 b0 b1 c0 c1 d0 d1
      | x == 34 -> do
      (b0, b1) <- getSackPair
      (c0, c1) <- getSackPair
      (d0, d1) <- getSackPair
      (e0, e1) <- getSackPair
      return $ OptionSack4 b0 b1 c0 c1 d0 d1 e0 e1
      | otherwise -> fail "bad option sack"

data TCPOption
  = OptionTS    Word32 Word32
  | OptionSack1 Word32 Word32
  | OptionSack2 Word32 Word32 Word32 Word32
  | OptionSack3 Word32 Word32 Word32 Word32 Word32 Word32
  | OptionSack4 Word32 Word32 Word32 Word32 Word32 Word32 Word32 Word32
  deriving (Eq, Ord, Show, Read, Generic)

-- instance Serialize TCPOption

instance Serialize TCPOptions where
  get = getOptions
  put = const $ return ()

testData :: ByteString
testData = pack $ map toEnum [1, 1, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 0]
