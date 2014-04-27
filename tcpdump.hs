import System.Environment
import Network.Pcap
import PreprocessPcap

main = do
  [fName] <- getArgs
  h <- openOffline fName
  let loop h = do
        r <- getNext h
        case r of
          Nothing -> return ()
          Just (_, r') -> do
            putStrLn . showLine $ r'
            loop h
  loop h
