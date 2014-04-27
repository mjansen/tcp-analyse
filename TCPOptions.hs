{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleInstances #-}

module TCPOptions where

import GHC.Generics
import Data.Serialize
import Data.Word
import Data.List (intercalate)
import Text.Printf

import Control.Applicative

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
  empty <- isEmpty
  case empty of
    True -> return $ TCPOptions []
    False -> (\o (TCPOptions os) -> TCPOptions (o:os)) <$> getOption <*> getOptions

getOption :: Get TCPOption
getOption = do
  optionKind <- getWord8
  case fromEnum optionKind of
    x | x == tcpOptionEND    -> return OptionEND
      | x == tcpOptionNOP    -> return OptionNOP
      | x == tcpOptionTS     -> getOptionTS
      | x == tcpOptionSack   -> getOptionSack
      | x == tcpOptionACD    -> getWord8 >>= skip . (+ (-2)) . fromEnum >> return OptionACD
      | x == tcpOptionMSS    -> getWord8 >> getWord16be   >> return OptionMSS
      | x == tcpOptionWS     -> getWord8 >> getWord8      >> return OptionWS
      | x == tcpOptionSackOK -> getWord8                  >> return OptionSackOK
      | x == tcpOptionACR    -> getWord8 >> getWord8      >> return OptionACR
      | otherwise            -> return OptionUnknown

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
  | OptionEND
  | OptionNOP
  | OptionSackOK
  | OptionACD
  | OptionMSS
  | OptionWS
  | OptionACR
  | OptionUnknown
  deriving (Eq, Ord, Show, Read, Generic)

showOptionsLike :: TCPOptions -> String
showOptionsLike (TCPOptions os) = intercalate "," . map showOptionLike $ os

showOptionLike :: TCPOption -> String
showOptionLike OptionNOP = "nop"
showOptionLike OptionEND = "end"
showOptionLike (OptionTS a b) = printf "TS val %d ecr %d" a b
showOptionLike (OptionSack1 a0 a1) = printf "sack 1 {%d:%d}" a0 a1
showOptionLike (OptionSack2 a0 a1 b0 b1) = printf "sack 2 {%d:%d}{%d:%d}" a0 a1 b0 b1
showOptionLike (OptionSack3 a0 a1 b0 b1 c0 c1) = printf "sack 3 {%d:%d}{%d:%d}{%d:%d}" a0 a1 b0 b1 c0 c1
showOptionLike (OptionSack4 a0 a1 b0 b1 c0 c1 d0 d1) = printf "sack 4 {%d:%d}{%d:%d}{%d:%d}{%d:%d}" a0 a1 b0 b1 c0 c1 d0 d1
showOptionLike _ = "other"

{-
    x | x == tcpOptionEND    -> return getOptions -- return $ TCPOptions []
      | x == tcpOptionNOP    -> getOptions
      | x == tcpOptionTS     -> getOptionTS   >>= getMoreOptions
      | x == tcpOptionSack   -> getOptionSack >>= getMoreOptions
      | x == tcpOptionACD    -> getWord8 >>= skip . (+ (-2)) . fromEnum  >> getOptions
      | x == tcpOptionMSS    -> getWord8 >> getWord16be   >> getOptions
      | x == tcpOptionWS     -> getWord8 >> getWord8      >> getOptions
      | x == tcpOptionSackOK -> getWord8 >> getOptions
      | x == tcpOptionACR    -> getWord8 >> getWord8      >> getOptions
-}

-- instance Serialize TCPOption

instance Serialize TCPOptions where
  get = getOptions
  put = const $ return ()

testData :: ByteString
testData = pack $ map toEnum [1, 1, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 0]
