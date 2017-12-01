//this file generate the part result of exp of each group and store it as 
//groupresult.txt
package main

import (
	"fmt"
	//"github.com/roasbeef/go-go-gadget-paillier"
	"io"
	"math/big"
	"crypto/rand"
	"time"
	mathrand "math/rand"

	"log"
	"os"
	"bufio"
	"encoding/json"
	"math"
	"gopkg.in/cheggaaa/pb.v1"
	"encoding/base64"
	"runtime"
	"sync"
	"flag"
)


var KEYSIZE = 1024
var DEBUG = true
const PL = 1360
const Mu = 3080
var GROUPElENUM = 1000 //400 is suitalbe for group size
var writelock *sync.RWMutex

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


type InterRsult struct{
	Result []byte
	Groupid int
}

func Red(msg string)(string){
	return "\x1b[31;1m" + msg + "\x1b[0m"
}


func Blue(msg string)(string){
	return "\x1b[34;1m" + msg + "\x1b[0m"
}



func  GenerateN(random io.Reader, bits int) (*big.Int, *big.Int, *big.Int, error) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	var p,q,N,p2,q21,p21,q2 *big.Int

		for true {
			p, _ = rand.Prime(random, bits/2)
			p2 = new(big.Int).Mul(two, p)
			p21 = new(big.Int).Add(one,p2)
			ret := p21.ProbablyPrime(10)
			if ret == true{
				fmt.Println("we found the P!")
				break
			}
		}

		for true {
		q, _ = rand.Prime(random, bits/2)
		q2 = new(big.Int).Mul(two, q)
		q21 = new(big.Int).Add(one,q2)
		ret := q21.ProbablyPrime(10)
		if ret == true{
			fmt.Println("we found the Q!")
			break
		}
		}

		N = new(big.Int).Mul(q21, p21)
		FiN := new(big.Int).Mul(p2,q2)
		//N,_:= rand.Prime(random, bits)
		//POW := new(big.Int).Exp(two, big.NewInt(int64(bits)),nil)
		//randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

		//N  = new(big.Int).Rand(randsource, POW)

	p, err := rand.Prime(random, bits)
			if err != nil {
				return nil,nil,nil,err
			}

	//g := new(big.Int).Exp(p, two, N)

	return N,p ,FiN, nil

}


func addJob(jobs chan<- int, num int) {

	for i:=0;i<num;i++{
		jobs <- i
	}
	//fmt.Println("num to calculate is ", num)
	close(jobs)

}

var colorflag = false
func doJob(
		jobs <-chan int, dones chan<- struct{},groups_v []*big.Int,
		part_calculated map[int]*big.Int, N *big.Int,
		w  *bufio.Writer ,ii int, bar *pb.ProgressBar){

	zero := big.NewInt(0)
	for job := range jobs{
		tmp := big.NewInt(3080)
		inner := time.Now()

		for j:=0;j<len(groups_v);j++{
			if j==job {
				continue
			//fmt.Println("..")
			}else{
				tmp = tmp.Exp(tmp,groups_v[j],N)
			}
		}

		msg := fmt.Sprintf("worker %d", ii)
		if colorflag == true {
			msg = Red(msg)
			colorflag = false
		}else{
			msg = Blue(msg)
			colorflag = true
		}
		if DEBUG == true {
			timeTrack(inner, msg)
		}
		part_calculated[job] = new(big.Int).Add(tmp,zero)
		val := InterRsult{tmp.Bytes(), job}
		marshed,_ := json.Marshal(val)
		//fmt.Println(marshed)
		writelock.Lock()
		w.WriteString(base64.StdEncoding.EncodeToString(marshed)+"\n")

		writelock.Unlock()
		bar.Increment()
	}
	dones <- struct{}{}

}

func Generate_W_V(Ws []*big.Int, v, N,G, FiN *big.Int, keys[]*Privkey ,num int){
	defer timeTrack(time.Now(), "calculate V,W")
	//one := big.NewInt(1)
	zero := big.NewInt(0)
	done := false
	var worker = runtime.NumCPU()
	working := worker
	jobs := make(chan int, worker)
	dones := make(chan struct{}, worker)
	fo, err := os.OpenFile("groupresult.txt", os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
	0600)
   	check(err)

	w := bufio.NewWriter(fo)
	u := big.NewInt(3080)
	localv := big.NewInt(1)
	v.Add(u, big.NewInt(0))
	ally := big.NewInt(1)
	group_num := math.Ceil(float64(num)/float64(GROUPElENUM))
	fmt.Println("group num:",group_num)
	var j=0
	groups_v := make([]*big.Int, 0)
	part_calculated := make(map[int]*big.Int)

	val := InterRsult{N.Bytes(), -1}
	marshed,_ := json.Marshal(val)
	w.WriteString(base64.StdEncoding.EncodeToString(marshed)+"\n")

	//marshed = append(marshed, '\n')
	//w.Write(marshed)

	val = InterRsult{FiN.Bytes(), -2}
	marshed,_ = json.Marshal(val)
	//marshed = append(marshed, '\n')
	//w.Write(marshed)
	w.WriteString(base64.StdEncoding.EncodeToString(marshed)+"\n")

	val = InterRsult{G.Bytes(), -3}
	marshed,_ = json.Marshal(val)
	//marshed = append(marshed, '\n')
	//w.Write(marshed)
	w.WriteString(base64.StdEncoding.EncodeToString(marshed)+"\n")
	//Ws[0] = big.NewInt(3080)
	creat_group := time.Now()
	if num <GROUPElENUM || num == GROUPElENUM {
		for i:=0;i<num;i++{
				ally.Mul(ally, keys[i].pub)
		}
		y := new(big.Int).Quo(ally, keys[0].pub)
		Ws[0] = new(big.Int).Exp(u,y,N)
		v.Exp(Ws[0], keys[0].pub, N)

		return

	}else {
		for i := 0; i < num; i++ {
			localv.Mul(localv, keys[i].pub)
			localv = new(big.Int).Mod(localv, FiN)

			if i%GROUPElENUM == GROUPElENUM-1 {
				groups_v = append(groups_v, new(big.Int).Add(localv, zero))
				localv=nil
				localv = big.NewInt(1)
				j++
			}
		}
		groups_v = append(groups_v,new(big.Int).Add(localv, zero))

		timeTrack(creat_group, "creating group")

		fmt.Println(len(groups_v))
		bar := pb.StartNew(len(groups_v)).Prefix("generate the part result")

		for j:=0;j<3;j++{
			Ws[j] = big.NewInt(3080)
		}
		creating_w := time.Now()
		go addJob(jobs, len(groups_v))
		for i:=0; i<worker; i++ {
			go doJob(jobs, dones,groups_v,part_calculated,N,w,i, bar)
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

		timeTrack(creating_w,"creating ws")
	}
	w.Flush()
	return
	w.WriteString("--------------------\n")
	barw := pb.StartNew(len(groups_v)).Prefix("generate the W")
	calculte3 := time.Now()
	for i:= 0;i<num;i++{
		Ws[i] =  new(big.Int).Quo(groups_v[i/num], keys[i].pub)
		Ws[i] = new(big.Int).Exp(part_calculated[i/num], Ws[0], N)
		w.WriteString(base64.StdEncoding.EncodeToString(Ws[i].Bytes())+"\n")
		barw.Increment()
	}

	timeTrack(calculte3, "for ws quo calculate")
	v.Exp(Ws[0], keys[0].pub, N)
	if err = w.Flush(); err != nil {
		panic(err)
	}
	if err := fo.Close(); err != nil {
            panic(err)
        }


	return
}




func generate_rand(N *big.Int)(*big.Int){
	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	r  := new(big.Int).Rand(randsource, N)
	return r
}



func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s took %s", name, elapsed)
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}


func main() {

	VoterNumber:= flag.Int("n", 900000, "voter numbers")
	keysize := flag.Int("k", 1024, "keysize numbers")
	//debug := flag.Bool("v", true, "verbose")
	groupnum := flag.Int("s" , 1024, "group element numbers")


	flag.Parse()

	NUM := *VoterNumber
	KEYSIZE = *keysize
	GROUPElENUM = *groupnum


	fmt.Println("----------------------")
	fmt.Println("voter number: ",NUM)
	fmt.Println("key size: ",KEYSIZE)
	fmt.Println("group number:", GROUPElENUM)
	fmt.Println("----------------------")

	//DEBUG = *debug
	var N,g,FiN *big.Int
	writelock = new(sync.RWMutex)
	need_generate := false
	if need_generate {
		N, g, FiN, _ = GenerateN(rand.Reader, KEYSIZE)
	}else {
		part_calculated := make(map[int]*big.Int)
		fiNg, err := os.Open("11.txt")
		check(err)
		r1 := bufio.NewReader(fiNg)
		for i:=0;i<3;i++ {

			line, err := r1.ReadBytes('\n')
			if err != nil && err != io.EOF {
				panic(err)
			}
			decodeval,err := base64.StdEncoding.DecodeString(string(line))
			var val InterRsult
			json.Unmarshal(decodeval, &val)
			part_calculated[val.Groupid] = new(big.Int).SetBytes(val.Result)

		}
		N = new(big.Int).Add(part_calculated[-1],big.NewInt(0))
		println(N.BitLen())
		FiN = new(big.Int).Add(part_calculated[-2],big.NewInt(0))
		println(FiN.BitLen())
		g = new(big.Int).Add(part_calculated[-3],big.NewInt(0))
		println(g.BitLen())
	}

	//fmt.Println(N.String())
	//fmt.Println(FiN.String())
	//fmt.Println(g)
	//NUM := 475081

	//NUM := 1000
	keys := make([]*Privkey,NUM,NUM)
	now := time.Now()

	fi, err := os.Open("output.txt")
	check(err)
	r := bufio.NewReader(fi)
    for i:=0; i<NUM;i++ {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		if len(line) == 0 {
			break
		}
		decodeval,err := base64.StdEncoding.DecodeString(string(line))
		var m PrivkeyByte
		json.Unmarshal(decodeval, &m)
		keys[i] = &Privkey{
			new(big.Int).SetBytes(m.Pub),new(big.Int).SetBytes(m.P),
			new(big.Int).SetBytes(m.Q)}
	}
	fmt.Println("key size in file", keys[3].pub.BitLen())
	if err := fi.Close(); err != nil {
		panic(err)
	}
	timeTrack(now, "Key generate")
	Ws := make([]*big.Int,NUM,NUM)
	V := big.NewInt(0)
	//fmt.Println("-----------")
	//fmt.Println(keys[2].pub.Bytes())
	Generate_W_V(Ws, V,N,g,FiN, keys, NUM)
	timeTrack(now, "all spet on data: ")
	return
}
