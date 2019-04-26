package hscrack

import (
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	tmcrypto "github.com/tendermint/tendermint/crypto"

	"github.com/orientwalt/usdp/accounts"
	"github.com/orientwalt/usdp/accounts/keystore"
)

//
func Unlock(encrypted, passphrase string) (tmcrypto.PrivKey, error) {
	account := accounts.Account{Address: encrypted}
	privkey, err := keystore.GetPrivKey(account, passphrase, "")
	if err != nil {
		return nil, err
	}
	return privkey, nil
}

var (
	totalTried uint64   = 0
	stopSearch int32    = 0
	resume     uint64   = 0
	lines      []string = nil
)

//
func UnlockBruteForce(encryptedKey, charset, pattern string, pwlen int) {
	chunks := 1
	chunk := 0
	if pattern != "" {
		pwlen = len(pattern)
	}
	var ncpu = runtime.NumCPU()
	runtime.GOMAXPROCS(ncpu)
	fmt.Printf("Number of CPUs: %d\n", ncpu)
	result := BruteChunk(ncpu, encryptedKey, charset, pattern, lines, pwlen, chunk, chunks, resume)
	if result == "" {
		fmt.Printf("\nNot found.\n")
	} else if strings.HasPrefix(result, "to resume") {
		fmt.Printf("Exiting... %s\n", result)
	} else {
		fmt.Printf("\n!!! FOUND !!!!\n%s\n", result)
	}
}

func searchRange(start, finish uint64, key, charset string, pwlen int, pat []rune, c chan string) {
	cset := []rune(charset)
	var i uint64

	var guess []rune = make([]rune, len(pat))

	for i = start; atomic.LoadInt32(&stopSearch) == 0 && i < finish; i++ {
		acum := i
		for j := 0; j < len(pat); j++ {
			if pat[j] == '?' {
				guess[j] = cset[acum%uint64(len(cset))]
				acum /= uint64(len(cset))
			} else {
				guess[j] = pat[j]
			}
		}
		guessString := string(guess)
		privKey, _ := Unlock(key, guessString)
		if privKey != nil {
			c <- key + "    pass = '" + guessString + "'   ( Address: " + key + " )"
			return
		}

		atomic.AddUint64(&totalTried, 1)

		fmt.Printf("%6d passphrases tried (latest guess: %s )                      \r", atomic.LoadUint64(&totalTried), guessString)
	}
	if atomic.LoadInt32(&stopSearch) != 0 {
		c <- fmt.Sprintf("%d", i-start) // interrupt signal received, announce our position for the resume code
		return
	}
	c <- ""
}

func tryPasswords(start, finish uint64, key string, passwords []string, c chan string) {
	var i uint64
	if finish > uint64(len(passwords)) {
		log.Fatal("INTERNAL ERROR: tryPasswords -- finish > len(passwords)!")
	}
	for i = start; atomic.LoadInt32(&stopSearch) == 0 && i < finish; i++ {
		privKey, _ := Unlock(key, passwords[i])
		if privKey != nil {
			c <- key + "    pass = '" + passwords[i] + "'   ( Address: " + key + " )"
			return
		}

		atomic.AddUint64(&totalTried, 1)

		fmt.Printf("%6d passphrases tried (latest guess: %s )                       \r", atomic.LoadUint64(&totalTried), passwords[i])
	}
	if atomic.LoadInt32(&stopSearch) != 0 {
		c <- fmt.Sprintf("%d", i-start) // interrupt signal received, announce our position for the resume code
		return
	}
	c <- ""
}

//
func BruteChunk(routines int, key, charset, pattern string, passwords []string, pwlen, chunk, chunks int, resume uint64) string {

	if charset == "" && passwords == nil {
		charset = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~."
	}

	if charset != "" {
		fmt.Printf("Using character set: %s\n", charset)
	}
	spaceSize := uint64(math.Pow(float64(len(charset)), float64(pwlen)))

	if passwords == nil {
		if len([]rune(pattern)) != 0 {
			fmt.Printf("Pattern: %s\n", pattern)
			fmt.Printf("Unknown chars: %d\n", pwlen)
			fmt.Printf("Password length: %d\n", len([]rune(pattern)))
		} else {
			pattern = ""
			for i := 0; i < pwlen; i++ {
				pattern = pattern + "?"
			}
			fmt.Printf("Password length: %d\n", pwlen)
		}
		fmt.Printf("Total passphrase space size: %d\n", spaceSize)
	} else {
		spaceSize = uint64(len(passwords))
		fmt.Printf("Number of passphrases to try: %d\n", len(passwords))
	}

	patAsRunes := []rune(pattern)
	startFrom := uint64(0)
	chunkSize := spaceSize / uint64(chunks)
	blockSize := uint64(chunkSize / uint64(routines))
	if chunks > 1 {
		startFrom = chunkSize * uint64(chunk)
		csz := chunkSize
		if chunk == chunks-1 {
			csz = spaceSize - startFrom
		}
		fmt.Printf("Chunk passphrase space size: %d  Starting from point: %d\n", csz, startFrom)
	}

	totalTried = resume * uint64(routines)
	c := make(chan string)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	defer signal.Stop(sigc)

	for i := 0; i < routines; i++ {
		var finish uint64
		if i == routines-1 {
			// Last block needs to go right to the end of the search space
			finish = chunkSize + startFrom
			if chunk == chunks-1 {
				finish = spaceSize
			}
		} else {
			finish = uint64(i)*blockSize + blockSize + startFrom
		}
		start := uint64(i)*blockSize + startFrom + resume

		if passwords == nil {
			go searchRange(start, finish, key, charset, pwlen, patAsRunes, c)
		} else {
			go tryPasswords(start, finish, key, passwords, c)
		}
	}

	var minResumeKey uint64 = 0
	i := routines
	for {
		select {
		case s := <-c:
			if s == "" {
				// a search thread has ended!
				i--
				if i <= 0 {
					return "" // last search thread ended!
				}
			} else if atomic.LoadInt32(&stopSearch) != 0 {
				u, err := strconv.ParseUint(s, 10, 64)
				if err == nil && (u+resume < minResumeKey || minResumeKey == 0) {
					minResumeKey = u + resume
				} else if err != nil {
					// happened to crack key on interrupt! return cracked key
					return s
				}
				i--
				if i <= 0 {
					return fmt.Sprintf("to resume, use offset %d", minResumeKey)
				}
			} else { // found/cracked key! return answer!
				return s
			}
		case sig := <-sigc:
			atomic.StoreInt32(&stopSearch, 1) // tell search functions they need to stop
			fmt.Printf("\n(%s)\n", sig.String())
		}
	}
}
