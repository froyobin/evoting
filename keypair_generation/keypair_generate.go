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
	"time"
	"log"
	"flag"
	"encoding/base64"
	"sync"
	"runtime"
	"os/exec"
	"strings"
	"strconv"
	_ "net/http/pprof"
	"net/http"
)
var  KEY_SIZE = 1024
const DEFAULT_POOL_SIZE = 100000000
//const VALUE_SIZE = 88
var colorflag = false
var load_file = false
var indexI int= 0
var indexJ int= 0
var writelock *sync.RWMutex
var writelockoutputkey *sync.RWMutex
var searchdone = false
var one = big.NewInt(1)
var two = big.NewInt(2)


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

func GenerateKeypreprime(random io.Reader, bits int, Primepool *[]*big.Int) (PrivkeyByte,
	error) {

	pubkey := big.NewInt(1)
	localprimepool := *Primepool
	var p *big.Int
	var q *big.Int
	defer  func (){
		error := recover()
		if error == nil{
			return
		}
			searchdone = true
			return
		}()
	for true {

		writelock.Lock()

		p = localprimepool[indexI]
		q = localprimepool[indexJ]

		indexJ = indexJ+1
		if indexJ >= len(*Primepool){
			println(Blue("we are recyclying the memory"))
			*Primepool = localprimepool[1:]
			indexJ = indexI+1
		}
		if len(*Primepool) == 1{
			searchdone = true
		}
		writelock.Unlock()
		if searchdone == true{
			break
		}
		pp := new(big.Int).Mul(two, p)
		pubkey = new(big.Int).Add(one,new(big.Int).Mul(q, pp))
		if pubkey.ProbablyPrime(5)== true{
			break
		}
	}
	if searchdone == true{
		return PrivkeyByte{}, nil
	}
	key := PrivkeyByte{pubkey.Bytes(), p.Bytes(), q.Bytes()}
		return key, nil

}

func GenerateKey(random io.Reader, bits int) (PrivkeyByte,error) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	pubkey := big.NewInt(1)
	p := big.NewInt(1)
	q := big.NewInt(1)
	var err error
	for true {
		primesearch := time.Now()
		p, err = rand.Prime(random, bits/2)
		if err != nil {
			return PrivkeyByte{}, err
		}
		timeTrack(primesearch, "search")
		q, err = rand.Prime(random, bits/2)
		if err != nil {
			return PrivkeyByte{}, err
		}
		timenow := time.Now()
		pp := new(big.Int).Mul(two, p)
		timeTrack(timenow, "times 2")
		timenow = time.Now()
		pubkey = new(big.Int).Add(one,new(big.Int).Mul(q, pp))
		timeTrack(timenow, "together")
		if pubkey.ProbablyPrime(10)== true{
			break
		}

	}
	key := PrivkeyByte{pubkey.Bytes(), p.Bytes(), q.Bytes()}
		return key, nil
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



func doJob(
		jobs <-chan int, dones chan<- struct{},
		w  *bufio.Writer ,ii int, bar *pb.ProgressBar, PrimePool *[]*big.Int){

	defer  func (){
		dones <- struct{}{}
	}()


	for range jobs{
		//inner := time.Now()
		var val PrivkeyByte
		if PrimePool == nil {
			val, _ = GenerateKey(rand.Reader, KEY_SIZE)
		} else{
			val, _= GenerateKeypreprime(rand.Reader, KEY_SIZE,PrimePool)
		}
		if searchdone == true{
			bar.Finish()
			break
		}
		marshed,_ := json.Marshal(val)

		writelockoutputkey.Lock()
		if _, err := w.WriteString(base64.StdEncoding.EncodeToString(marshed)+"\n"); err != nil {
			writelockoutputkey.Unlock()
			panic(err)
			}
		writelockoutputkey.Unlock()
		 msg := fmt.Sprintf("worker %d", ii)
				if colorflag == true {
						msg = Red(msg)
						colorflag = false
				}else{
						msg = Blue(msg)
						colorflag = true
				}
		//timeTrack(inner, msg)
		bar.Increment()


	}
	dones <- struct{}{}

}




func Loadfiletomemory(primefilepath string, PrimePool *[]*big.Int)(errret error){

	println(Blue("Evaluating the file loading time...."))
	cmd := exec.Command("wc", "-l", primefilepath)

	out, err := cmd.Output()
    if err != nil {
        fmt.Println(err)
    }
	//var raw_data string
	var val []byte
	//var errdecode error
	var output *big.Int

	line_nums := strings.Split(string(out)," ")
    line_num,err := strconv.Atoi(line_nums[0])
	bar := pb.StartNew(line_num).Prefix("loading primes from file")
	fread, err := os.Open(primefilepath)
	//if  err != nil{
	//  println("error in file path")
	//  return
	//}
	//fileio := bufio.NewReader(fread)
	//defer func (){
	//	fread.Close()
	//	fileio.Discard(fileio.Buffered())
	//	println("we discard the file cache")
	//}()

	//io.ReadFull(fread, content)
	newreader := bufio.NewReader(fread)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//num_content := len(content)
	//fixme we set only half of the pool
	for j:=0;j<line_num/5;j++{
		//fmt.Printf("%s\n", content[k:k+88])
		//if k > num_content{
		//	break
		//}
		each,_,_ := newreader.ReadLine()
		val,_ = base64.StdEncoding.DecodeString(string(each))
		output = new(big.Int).SetBytes(val)
		//fmt.Println(output.BitLen())
		//k = k+VALUE_SIZE+1
		*PrimePool = append(*PrimePool, output)
		bar.Increment()
		//println(output.String())
		//panic("stop")
	}

	//var i=0
	//for true{
	//	raw_data, err = fileio.ReadString('\n')
	//	if err != nil{
	//		//println(err)
	//		break
	//	}
	//	if err == io.EOF{
	//		errret = nil
	//		break
	//	}
	//	if err != nil{
	//		println(err)
	//		errret = err
	//		break
	//	}
	//	val, errdecode = base64.StdEncoding.DecodeString(raw_data)
	//	//val, errdecode = base64.StdEncoding.DecodeString(raw_data)
	//	if errdecode != nil{
	//		println(errdecode)
	//	}
	//
	//	output = new(big.Int).SetBytes(val)
	//	fmt.Println(output.String())
	//	panic("test")
	//	*PrimePool = append(*PrimePool, output)
	//	bar.Increment()
	//
	//}

	fread.Close()
	bar.Finish()
	return errret
}



func main(){
	go func() {
	http.ListenAndServe("localhost:9090", nil)
	}()
	KeyPairNumPtr:= flag.Int("n", 100, "number of keypairs")
	PrimePathPtr := flag.String("Pfile", "", "location of prime file")
	OutFile := flag.String("O", "outputkey.txt", "location destination file")
	keysize := flag.Int("key", 1024, "set the size of the key")
  	flag.Parse()
	PrimePool := make([]*big.Int, 0, DEFAULT_POOL_SIZE)
	writelock = new(sync.RWMutex)
	writelockoutputkey = new(sync.RWMutex)
	KEY_SIZE = *keysize
	//arg := os.Args[1]
 	//i64,err := strconv.ParseInt(arg, 10, 32)
	done := false
	NUM := *KeyPairNumPtr
	primefilepath := *PrimePathPtr
	fmt.Println("*************************")
	fmt.Println("KEY SIZE: ",KEY_SIZE)
	fmt.Println("out file: ",*OutFile)
	fmt.Println("fime file: ",primefilepath)
	fmt.Println("keypair numbers: ",NUM)

	fmt.Println("*************************")

	if primefilepath == ""{
		load_file = false
	}else{
		load_file = true
		err := Loadfiletomemory(primefilepath, &PrimePool)
		if err != nil{
			println("error in load prime number")
			return
		}
	}
	//for true{
	//	println("sleep....")
	//	time.Sleep(1*time.Minute)
	//}
	bar := pb.StartNew(NUM).Prefix("uploadint the votes:")
	fo, err := os.OpenFile(*OutFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
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
		if load_file == true{
			go doJob(jobs, dones,w,i, bar, &PrimePool)
		} else{
			go doJob(jobs, dones,w,i, bar, nil)
		}
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

	if searchdone == true{
		println(Red("not enough prime to search"))
	}
	//buf := make([]Privkey, 1024)
	//for i:=0;i<NUM;i++ {
	//	val,_ :=  GenerateKey(rand.Reader, KEY_SIZE)
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
