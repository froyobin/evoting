package main

import (

	"io"
	"math/big"
	"crypto/rand"

	"fmt"
	"os"
	"bufio"
	"encoding/json"
	"gopkg.in/cheggaaa/pb.v1"

	"runtime"
	"time"
	"log"
	"encoding/base64"

	"sync"
	"flag"
)
var  KEY_SIZE = 2048
var colorflag = false

type Privkey struct{
	pub *big.Int
	p *big.Int
	q *big.Int
}

type PrivkeyByte struct{
	Pub []byte
	Q []byte
	P []byte
}

type Chunk struct {
	Keys []PrivkeyByte
	size  int
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func Red(msg string)(string){
        return "\x1b[31;1m" + msg + "\x1b[0m"
}


func Blue(msg string)(string){
        return "\x1b[34;1m" + msg + "\x1b[0m"
}


func GeneratePrime(random io.Reader, bits int) ([]byte,error) {

	p := big.NewInt(1)
	var err error
	//for true {
		p, err = rand.Prime(random, bits/2)
		if err != nil {
			return []byte("error"), err
		}

	//}
	//key := PrivkeyByte{pubkey.Bytes(), p.Bytes(), q.Bytes()}
		return p.Bytes(), nil
	}
//
func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s took %s", name, elapsed)
}

func addJob(jobs chan<- int, num int) {

	for i:=0;i<num;i++{
		jobs <- i
	}
	fmt.Println("num to calculate is ", num)
	close(jobs)

}

var writelock *sync.RWMutex
func doJob(
		jobs <-chan int, dones chan<- struct{},
		w  *bufio.Writer ,ii int, bar *pb.ProgressBar){

	for range jobs{
		//inner := time.Now()
		val,_ :=  GeneratePrime(rand.Reader, KEY_SIZE)
		put_val := base64.StdEncoding.EncodeToString(val)
		put_val = put_val + "\n"
		writelock.Lock()
		if _, err := w.Write([]byte(put_val)); err != nil {
            panic(err)
        	}
		writelock.Unlock()
		//if _, err := w.Write([]byte("\n")); err != nil {
         //   panic(err)
        	//}

		 fmt.Sprintf("worker %d", ii)
                if colorflag == true {
                        //msg = Red(msg)
                        colorflag = false
                }else{
                        //msg = Blue(msg)
                        colorflag = true
                }
		//timeTrack(inner, msg)


		bar.Increment()

	}
	dones <- struct{}{}

}


func main(){
	KeyPairNumPtr:= flag.Int("n", 100, "number of keypairs")
	keysize := flag.Int("s", 1024, "size of the key")
	flag.Parse()
	done := false
	writelock = new(sync.RWMutex)
	NUM := *KeyPairNumPtr
	KEY_SIZE = *keysize
	fmt.Println("choose key lenth:",KEY_SIZE)
	bar := pb.StartNew(NUM).Prefix("uploadint the votes:")
	fo, err := os.OpenFile("outputprime.txt", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
   	check(err)
     //close fo on exit and check for its returned error
    defer func() {
        if err := fo.Close(); err != nil {
            panic(err)
        }
    }()


	w := bufio.NewWriter(fo)


	var worker = runtime.NumCPU()
	working := worker
	jobs := make(chan int, worker)
	dones := make(chan struct{}, worker)
	go addJob(jobs, NUM)


	for i:=0; i<worker; i++ {
			go doJob(jobs, dones,w,i, bar)
		}
		for{
			<-dones
			working -= 1
			if working <= 0 {
				done = true
			}
			if done ==true{
				break
			}

		}


	//buf := make([]Privkey, 1024)
	//for i:=0;i<NUM;i++ {
	//	val,_ :=  GeneratePrime(rand.Reader, KEY_SIZE)
	//	marshed,_ := json.Marshal(val)
	//	marshed = append(marshed, '\n')
	//	if _, err := w.Write(marshed); err != nil {
     //       panic(err)
     //   	}
	//bar.Increment()
	//}

	if err = w.Flush(); err != nil {
        		panic(err)
	}


	bar.FinishPrint("done")
	return


	fi, err := os.Open("output.txt")
	check(err)

	r := bufio.NewReader(fi)

    for {
		// read a chunk
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		//fmt.Println(line)
		if len(line) == 0 {
			break
		}
		var m PrivkeyByte
		json.Unmarshal(line, &m)
		fmt.Println(new(big.Int).SetBytes(m.Pub))
	}



        if err := fo.Close(); err != nil {
            panic(err)
        }

}
