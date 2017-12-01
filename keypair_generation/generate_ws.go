//this file generate ws it needs
//key pairs file
// partresult file
// output to resultws.txt
package main

import (
	"fmt"
	//"github.com/roasbeef/go-go-gadget-paillier"
	"io"
	"math/big"
	"crypto/rand"
	"time"
	mathrand "math/rand"

	"crypto/sha256"
	"log"
	"os"
	"bufio"
	"encoding/json"
	"math"
	"gopkg.in/cheggaaa/pb.v1"
	"runtime"
	"encoding/base64"

	//"golang.org/x/tools/cmd/fiximports/testdata/src/titanic.biz/bar"
	"flag"
)


const PK = 256
const PL = 1360
const Mu = 3080
var GROUPElENUM = 400 //400 is suitalbe for group size
//const This_SIG = 5888

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



//func GenerateN(random io.Reader, bits int) (*big.Int, *big.Int, error) {
//	two := big.NewInt(2)
//	var N *big.Int
//	p,_ := rand.Prime(random, bits/2)
//	q,_ := rand.Prime(random, bits/2)
//	N = new(big.Int).Mul(p,q)
//	//N,_:= rand.Prime(random, bits)
//	//POW := new(big.Int).Exp(two, big.NewInt(int64(bits)),nil)
//	//randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
//
//	//N  = new(big.Int).Rand(randsource, POW)
//	ret := N.ProbablyPrime(1024)
//	fmt.Println(ret)
//
//
//	p, err := rand.Prime(random, bits/2)
//			if err != nil {
//				return nil,nil,err
//			}
//
//	g := new(big.Int).Exp(p, two, N)
//
//	return N,g ,nil
//
//
//}
func GenerateKey(random io.Reader, bits int) (*Privkey,error) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	pubkey := big.NewInt(1)
	p := big.NewInt(1)
	q := big.NewInt(1)
	var err error
	for true {
		p, err = rand.Prime(random, bits/2)
		if err != nil {
			return nil, err
		}

		q, err = rand.Prime(random, bits/2)
		if err != nil {
			return nil, err
		}
		pp := new(big.Int).Mul(two, p)
		pubkey = new(big.Int).Add(one,new(big.Int).Mul(q, pp))
		if pubkey.ProbablyPrime(10)== true{
			break
		}

	}
	key := &Privkey{pubkey, p, q}
		return key, nil
	}


func addJob(jobs chan<- int, num int) {

	for i:=0;i<num;i++{
		jobs <- i
	}
	//fmt.Println("num to calculate is ", num)
	close(jobs)

}



func doJob(
		jobs <-chan int, dones chan<- struct{},
		 Ws []*big.Int, part_calculated map[int]*big.Int,
		N, FiN *big.Int, ii int, keys[]*Privkey,bar *pb.ProgressBar){
	for job := range jobs{

		timenow := time.Now()

		index := job/GROUPElENUM
		localv := big.NewInt(1)
		pos := 0
		for i:=0;i<GROUPElENUM;i++{
			pos = index*GROUPElENUM+i
			if pos == job{
				continue
			}
			if pos == len(keys)|| pos >len(keys) {
				break
			}
			val := keys[pos].pub
			localv.Mul(localv, val)
			localv.Mod(localv, FiN)

		}


		//Ws[job] = new(big.Int).Quo(groups_v[job/GROUPElENUM], keys[job].pub)
		//Ws[job] = new(big.Int).Mod(Ws[job], FiN)
		Ws[job] = new(big.Int).Exp(part_calculated[job/GROUPElENUM], localv, N)

		//fmt.Println(Ws[job])
		//msg := fmt.Sprintf("worker %d", ii)
		//if colorflag == true {
		//	msg = Red(msg)
		//	colorflag = false
		//}else{
		//	msg = Blue(msg)
		//	colorflag = true
		//}
		//timeTrack(inner, msg)
		bar.Increment()
		//log.Printf("%s", msg)
		timeTrack(timenow,"spend on generating ws: ")

		}
	dones <- struct{}{}
}

func run_core_task(userid int, keys[]*Privkey,
		 Ws []*big.Int, N,g,V *big.Int,MSG string, error_record []int){

	This_SIG := userid


	Aa := make([]*big.Int,3,3)
	As := make([]*big.Int, 3, 3)
	hpi := big.NewInt(0)
	gpi := big.NewInt(0)
	generateA(keys[This_SIG], As, Aa, Ws, N, gpi, hpi, This_SIG)
	agroup := make([]*big.Int, 3, 3)
	alphagroup := make([]*big.Int, 3, 3)
	alphay := big.NewInt(0)
	pqgroup := make([]*big.Int, 2, 2)
	generate_groupparams(agroup, alphagroup, pqgroup, alphay, N)
	Tgroup := make([]*big.Int, 6, 6)
	generate_Tgroup(Tgroup, As, agroup, alphagroup, pqgroup, N, g, gpi, hpi, alphay)
	C := big.NewInt(0)

	Zgroup := generate_Zgroup(
		Tgroup, As, Aa, agroup, alphagroup, pqgroup, N, alphay, V, []byte(MSG), keys[This_SIG], C)

	//fixme we create piy here
	piy := new(big.Int).Exp(g, new(big.Int).Add(keys[This_SIG].p, keys[This_SIG].q), N)

	Tp := make([]*big.Int, 6, 6)
	generate_Tpgroup(g, alphagroup[2], keys[This_SIG].q,
		keys[This_SIG].p, piy, alphay, keys[This_SIG].pub, C, V, gpi,
		hpi, N, Zgroup, pqgroup, As, Aa, Ws, Tp)

	for i := 0; i < 6; i++ {
		//fmt.Println(Tgroup[i],"\n",Tp[i])
		if Tgroup[i].Cmp(Tp[i]) == 0 {
			//fmt.Println(Tp[i].Bytes())
			continue
		} else {
			fmt.Println("error: ", i)
			fmt.Println("=============")
			fmt.Println(Tgroup[i])
			fmt.Println("=============")
			fmt.Println(Tp[i])
			fmt.Println("=============")
			error_record = append(error_record,1)
			msg := fmt.Sprintf("error found in %d", userid)
			log.Printf(Red(msg))
			panic("err")

		}

	}


}


func doJob2(
		jobs <-chan int, dones chan<- struct{},
		  Ws []*big.Int, N,g,V *big.Int,
		 keys[]*Privkey,bar *pb.ProgressBar, MSG string, error_record []int){
	for job := range jobs{

		run_core_task(job, keys, Ws, N, g,V, MSG, error_record)

		bar.Increment()

		}
	dones <- struct{}{}
}





func Generate_W_V_from_file(Ws []*big.Int, v, N, FiN *big.Int, keys[]*Privkey ,
		part_calculated map[int]*big.Int, num int){
	//defer timeTrack(time.Now(), "calculate V,W")
	//one := big.NewInt(1)
	//zero := big.NewInt(0)
	done := false
	u := big.NewInt(3080)
	//localv := big.NewInt(1)
	v.Add(u, big.NewInt(0))
	//ally := big.NewInt(1)
	group_num := math.Ceil(float64(num)/float64(GROUPElENUM))
	fmt.Println("group num:",group_num)
	//var j=0
	//groups_v := make([]*big.Int, 0)

	//if num <GROUPElENUM || num == GROUPElENUM {
	//	for i:=0;i<num;i++{
	//			ally.Mul(ally, keys[i].pub)
	//	}
	//	y := new(big.Int).Quo(ally, keys[0].pub)
	//	Ws[0] = new(big.Int).Exp(u,y,N)
	//	v.Exp(Ws[0], keys[0].pub, N)
	//	return
	//
	//}else {
	//	for i := 0; i < num; i++ {
	//		//thistime := time.Now()
	//		localv.Mul(localv, keys[i].pub)
	//		if i%GROUPElENUM == GROUPElENUM-1 {
	//			groups_v = append(groups_v, new(big.Int).Add(localv, zero))
	//			localv = big.NewInt(1)
	//			//timeTrack(thistime,"this time.")
	//		}
	//	}
	//	groups_v = append(groups_v,new(big.Int).Add(localv, zero))
	//}

	barw := pb.StartNew(num).Prefix("generate the W")
	calculte3 := time.Now()

	var worker = runtime.NumCPU()
	working := worker
	jobs := make(chan int, worker)
	dones := make(chan struct{}, worker)
	go addJob(jobs, num)

	for i:=0; i<worker; i++ {
			go doJob(jobs, dones,Ws,part_calculated,N,FiN, i, keys,barw)
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




	//rtest := big.NewInt(3080)
	//for i:=0;i<len(groups_v);i++{
	//	if i ==0{
	//		break
	//	}
	//	rtest.Exp(rtest, groups_v[i], N)
	//}


	//for i:= 497;i<502;i++{
	//	fmt.Println(i/GROUPElENUM)
	//	Ws[i] =  new(big.Int).Quo(groups_v[i/GROUPElENUM], keys[i].pub)
	//	Ws[i] = new(big.Int).Exp(part_calculated[i/GROUPElENUM], Ws[i], N)
	//}

	timeTrack(calculte3, "for ws quo calculate")
	v.Exp(Ws[0], keys[0].pub, N)
	//fmt.Println(v.Bytes())
	//fmt.Println(Ws[0].Bytes())
	//fmt.Println(new(big.Int).Exp(Ws[1],keys[1024].pub,N).Bytes())
	//panic("done")

	//v2 := new(big.Int).Exp(Ws[501], keys[501].pub, N)
	//fmt.Println(v2)
	barw.Finish()
	return
}


func generateA(
		key *Privkey,As,a,Ws []*big.Int, N, gpi,hpi *big.Int,
		This_SIG int)(error){
		//defer timeTrack(time.Now(), "generate A")
	two := big.NewInt(2)
	//a := make([]*big.Int,3,3)
	//As = make([]*big.Int,3,3)
	//range_halfbits := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bits/2)),nil)
	for i:=0;i<3;i++ {

		//p := generate_rand(range_halfbits)
		//p.Mod(p, N)
		a[i] = generate_rand(N)
	}

	//tmp1, err := rand.Prime(random, bits/2)
	//		if err != nil {
	//			return err
	//		}
	//tmp2, err := rand.Prime(random, bits/2)
	//		if err != nil {
	//			return err
	//		}
	tmp1 := generate_rand(N)
	tmp2 := generate_rand(N)

	gpi = gpi.Exp(tmp1, two, N)
	hpi = hpi.Exp(tmp2,two,N)
	//fixme we use the first user as the signer
	W := Ws[This_SIG]
	As[0] = new(big.Int).Mul(W, new(big.Int).Exp(hpi, a[0], N))
	As[0].Mod(As[0],N)
	tmpgp := new(big.Int).Exp(gpi, a[0],N)
	tmphp := new(big.Int).Exp(hpi, a[1], N)
	As[1] = new(big.Int).Mul(tmpgp, tmphp)
	As[1] = new(big.Int).Mod(As[1],N)
	As[2] = new(big.Int).Mul(new(big.Int).Exp(gpi, key.p,N),new(big.Int).Exp(hpi, a[2],N))
	As[2].Mod(As[2], N)


	return nil
}


func generate_rand(N *big.Int)(*big.Int){
	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	r  := new(big.Int).Rand(randsource, N)
	return r
}

func generate_groupparams(agroup, alphagroup, pqgroup []*big.Int, alphay *big.Int, N *big.Int){
		//defer timeTrack(time.Now(), "calculate G group")
	for i:= 0;i<3;i++{
		agroup[i] = generate_rand(N)
		alphagroup[i] = generate_rand(N)
	}
	alphay = alphay.Add(generate_rand(N), big.NewInt(0))
	range_n := new(big.Int).Exp(big.NewInt(2), big.NewInt(PK+Mu),nil)
	//fmt.Println(range_n)
	//return
	for i :=0;i<2;i++{
		pqgroup[i] = generate_rand(range_n)
		pqgroup[i].Mod(pqgroup[i], N)
	}
	return
}

func generate_Tgroup(Tgroup, A, agroup, alphagroup,pqgroup []*big.Int,N,g, gpi,hpi,
alphay *big.Int){
	//defer timeTrack(time.Now(), "Tgroup")

	var part1 *big.Int
	var part2 *big.Int

	Tgroup[0] = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(A[0], alphay, N),
			new(big.Int).ModInverse(new(big.Int).Exp(hpi, alphagroup[0], N),N)),
		N,
	)


	Tgroup[1] = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(gpi, agroup[0], N),
			new(big.Int).Exp(hpi, agroup[1], N),
		),
		N,
	)


	part1 = new(big.Int).ModInverse(new(big.Int).Exp(A[1], alphay,N),N)
	part2 = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(gpi, alphagroup[0], N),
			new(big.Int).Exp(hpi, alphagroup[1], N),
		),
		N,
	)

	Tgroup[2] = new(big.Int).Mod(
		new(big.Int).Mul(
			part1,
			part2,
		),
		N,
	)



	Tgroup[3] = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(g, pqgroup[0], N),
			new(big.Int).Exp(g, pqgroup[1], N),
		),
		N,
	)


	Tgroup[4] = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(gpi, pqgroup[0], N),
				new(big.Int).Exp(hpi, agroup[2], N),
			),
			N,
		)


	A32 := new(big.Int).Exp(A[2], big.NewInt(2), N)
	//pg2 := new(big.Int).Mul(pqgroup[1], big.NewInt(2))
	part1 = new(big.Int).ModInverse(new(big.Int).Exp(A32, pqgroup[1],N),N)
	//part11 := new(big.Int).ModInverse(new(big.Int).Exp(A[2], pg2,N),N)
	//fmt.Println(part1)
	//fmt.Println(part11)
	//fmt.Println("33333fffddddsdff")
	part2 = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(gpi, alphay, N),
			new(big.Int).Exp(hpi, alphagroup[2], N),
		),
		N,
	)

	Tgroup[5] = new(big.Int).Mod(
		new(big.Int).Mul(part1,part2),
		N)


	return
}


func generate_Zgroup(Tgroup, A,Aa, agroup, alphagroup,pqgroup []*big.Int,N,alphay,
V*big.Int, MSG []byte, key *Privkey, c *big.Int)([]*big.Int) {
		//defer timeTrack(time.Now(), "Z group")
	var totalbyte []byte
	for i:=0;i<len(A);i++{
		tmp := A[i].Bytes()
		totalbyte = append(totalbyte, tmp...)
	}
	for i:=0;i<len(Tgroup);i++{
		tmp := Tgroup[i].Bytes()
		totalbyte = append(totalbyte, tmp...)
	}
	totalbyte = append(totalbyte, V.Bytes()...)
	totalbyte = append(totalbyte, MSG...)
	h := sha256.New()
	//h1 := h.Sum(nil)[:10]
	h.Write(totalbyte)
	h1 := h.Sum(nil)
	c = c.Mod(new(big.Int).SetBytes(h1), N)
	Zgroup := make([]*big.Int, 9, 9)

	for i:=0;i<3;i++ {
		Zgroup[i] = new(big.Int).Sub(agroup[i], new(big.Int).Mul(c, Aa[i]))
	}

	Zgroup[3] =
	new(big.Int).Sub(alphagroup[0], new(big.Int).Mul(c,new(big.Int).Mul(Aa[0], key.pub)))

	Zgroup[4] =
	new(big.Int).Sub(
		alphagroup[1], new(big.Int).Mul(
			c,new(big.Int).Mul(Aa[1], key.pub)))


	Zgroup[5] =
			new(big.Int).Sub(alphagroup[2], new(big.Int).Mul(
			c,new(big.Int).Mul(new(big.Int).Mul(Aa[2],big.NewInt(2)), key.q)))

	Zgroup[6] = new(big.Int).Sub(alphay, new(big.Int).Mul(c,key.pub))

	halfL := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(PL/2)), N)




	phalfL := new(big.Int).Sub(key.p, halfL)
	qhalfL := new(big.Int).Sub(key.q, halfL)

	cphalfL := new(big.Int).Mul(c, phalfL)
	cqhalfL := new(big.Int).Mul(c, qhalfL)

	Zgroup[7] = new(big.Int).Sub(pqgroup[0],cphalfL)
	Zgroup[8] = new(big.Int).Sub(pqgroup[1],cqhalfL)

	return Zgroup


	//	hashval := new(big.Int).SetBytes(h1)

}


func generate_Tpgroup(
		g,org, q,p,piy,alphay,Y,C, V, gpi,hpi,N *big.Int, Zgroup,pqgroup, As , Aa, Ws,
		Tp[]*big.Int){
		//defer timeTrack(time.Now(), "Tp group:")
	zero := big.NewInt(0)
	var part1, part2, tmp *big.Int
	//tmp = new(big.Int).Abs(Zgroup[6])
	tmp = new(big.Int).Exp(As[0], new(big.Int).Abs(Zgroup[6]), N)
	if Zgroup[6].Cmp(zero)<0 {
		tmp.ModInverse(tmp,N)

	}
	part1 = new(big.Int).Mod(
			new(big.Int).Mul(new(big.Int).Exp(V, C, N),tmp),
			N)

	//return part1

	//tmp = new(big.Int).Exp(As[0], new(big.Int).Abs(Zgroup[3]), N)
	part2 = new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[3]), N)
	if Zgroup[3].Cmp(zero)>0 {

		part2.ModInverse(part2,N)

	}

	Tp[0] = new(big.Int).Mod(
		new(big.Int).Mul(part1,part2),
		N)


	A2c := new(big.Int).Exp(As[1], C, N)
	gza1 := new(big.Int).Exp(gpi, new(big.Int).Abs(Zgroup[0]), N)
	if Zgroup[0].Cmp(zero)<0{
		gza1.ModInverse(gza1, N)
	}
	gza2 := new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[1]), N)
	if Zgroup[1].Cmp(zero)<0{
		gza2.ModInverse(gza2, N)
	}
	Tp[1] = new(big.Int).Mod(
		new(big.Int).Mul(A2c,new(big.Int).Mul(gza1,gza2)),N)



	A2Zy := new(big.Int).Exp(As[1], new(big.Int).Abs(Zgroup[6]), N)
	if Zgroup[6].Cmp(zero)>0 {
		A2Zy.ModInverse(A2Zy,N)

	}
	gzaf1 := new(big.Int).Exp(gpi, new(big.Int).Abs(Zgroup[3]),N)
	if Zgroup[3].Cmp(zero)<0{
		gzaf1.ModInverse(gzaf1, N)
	}
	gzaf2 := new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[4]),N)
	if Zgroup[4].Cmp(zero)<0{
		gzaf2.ModInverse(gzaf2, N)
	}
	part1 = new(big.Int).Mul(gzaf1, gzaf2)
	Tp[2] = new(big.Int).Mod(
		new(big.Int).Mul(part1, A2Zy),N)



	halfL := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(PL/2)), N)
	gzp := new(big.Int).Exp(g, new(big.Int).Abs(Zgroup[7]), N)
	if Zgroup[7].Cmp(zero)<0{
		gzp.ModInverse(gzp, N)
	}
	g2l := new(big.Int).Exp(g, new(big.Int).Mul(halfL, C), N)
	g2l.ModInverse(g2l, N)
	gzp2l := new(big.Int).Mul(g2l, gzp)


	gzp2 := new(big.Int).Exp(g, new(big.Int).Abs(Zgroup[8]), N)
	if Zgroup[8].Cmp(zero)<0{
		gzp.ModInverse(gzp, N)
	}
	g2l2 := new(big.Int).Exp(g, new(big.Int).Mul(halfL, C), N)
	g2l2.ModInverse(g2l2, N)
	gzq2l := new(big.Int).Mul(g2l2, gzp2)

	part1 = new(big.Int).Mul(gzp2l, gzq2l)

	piyc := new(big.Int).Exp(piy, C, N)
	Tp[3] = new(big.Int).Mul(piyc, part1)
	Tp[3].Mod(Tp[3], N)


	gzp = new(big.Int).Exp(gpi, new(big.Int).Abs(Zgroup[7]), N)
	if Zgroup[7].Cmp(zero)<0{
		gzp.ModInverse(gzp, N)
	}
	g2l = new(big.Int).Exp(gpi, new(big.Int).Mul(halfL, C), N)
	g2l.ModInverse(g2l, N)
	gzp2l = new(big.Int).Mul(g2l, gzp)
	hza3 := new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[2]), N)
	if Zgroup[2].Cmp(zero)<0{
		hza3.ModInverse(hza3, N)
	}
	A3c := new(big.Int).Exp(As[2], C, N)
	Tp[4] = new(big.Int).Mul(
		A3c, new(big.Int).Mul(hza3, gzp2l))
	Tp[4].Mod(Tp[4], N)



	//last one

	gc := new(big.Int).Exp(gpi, C, N)
	A32 := new(big.Int).Exp(As[2], big.NewInt(2), N)
	gzp2 = new(big.Int).Exp(A32, new(big.Int).Abs(Zgroup[8]), N)

	if Zgroup[8].Cmp(zero)>0{
		gzp2.ModInverse(gzp2, N)
	}

	g2l2 = new(big.Int).Exp(A32, new(big.Int).Mul(halfL, C), N)
	out1 := new(big.Int).Mul(g2l2, gzp2)

	out1.Mul(out1,gc)

	gzy := new(big.Int).Exp(gpi, new(big.Int).Abs(Zgroup[6]), N)
	if Zgroup[6].Cmp(zero)<0{
		gzy.ModInverse(gzy, N)
	}
	hal3 := new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[5]), N)
	if Zgroup[5].Cmp(zero)<0{
		hal3.ModInverse(hal3, N)
	}

	gzyhal3 := new(big.Int).Mul(gzy, hal3)
	out1.Mul(out1, gzyhal3)
	Tp[5] = new(big.Int).Mod(out1, N)

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


	MSG := "hello"
	//fmt.Println(g)
	//NUM := 475081
	//NUM := 1390000
	//NUM := 12000
	//NUM := 1000000
	//NUM := 10001



	VoterNumber:= flag.Int("n", 900000, "voter numbers")
	//debug := flag.Bool("v", true, "verbose")
	groupnum := flag.Int("s" , 1024, "group element numbers")


	flag.Parse()


	NUM := *VoterNumber
	GROUPElENUM = *groupnum


	fmt.Println("----------------------")
	fmt.Println("voter number: ",NUM)
	fmt.Println("group number:", GROUPElENUM)
	fmt.Println("----------------------")

	time.Sleep(3*time.Second)

	keys := make([]*Privkey,NUM,NUM)
	now := time.Now()
	part_calculated := make(map[int]*big.Int)
	fi, err := os.Open("output.txt")
	check(err)
	fiWs, err := os.Open("groupresult.txt")
	check(err)

	defer func() {
        if err := fi.Close(); err != nil {
            panic(err)
        }
    }()

	defer func() {
        if err := fiWs.Close(); err != nil {
            panic(err)
        }
    }()


	r := bufio.NewReader(fi)
	rpart := bufio.NewReader(fiWs)
    for i:=0; i<NUM;i++ {
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
		decodeval,err := base64.StdEncoding.DecodeString(string(line))
		json.Unmarshal(decodeval, &m)
		keys[i] = &Privkey{
			new(big.Int).SetBytes(m.Pub),new(big.Int).SetBytes(m.P),
			new(big.Int).SetBytes(m.Q)}
	}

	for {
		line, err := rpart.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		//fmt.Println(line)
		if len(line) == 0 {
			break
		}
		decodeval,err := base64.StdEncoding.DecodeString(string(line))
		var val InterRsult
		json.Unmarshal(decodeval, &val)
		part_calculated[val.Groupid] = new(big.Int).SetBytes(val.Result)

	}
	N := new(big.Int).Add(part_calculated[-1],big.NewInt(0))
	FiN := new(big.Int).Add(part_calculated[-2],big.NewInt(0))

	//println(N.BitLen())
	g := new(big.Int).Add(part_calculated[-3],big.NewInt(0))
	//fmt.Println(N)
	//fmt.Println(g)
	//return

	timeTrack(now, "Key generate")
	Ws := make([]*big.Int,NUM,NUM)
	//Aa := make([]*big.Int,3,3)
	V := big.NewInt(0)
	fmt.Println(keys[2].pub.BitLen())
	Generate_W_V_from_file(Ws, V,N, FiN, keys, part_calculated, NUM)

	//we write the W to file
	foW, err := os.OpenFile("outputWs.txt", os.O_CREATE|os.O_WRONLY, 0600)
   	check(err)
     //close fo on exit and check for its returned error
    defer func() {
        if err := foW.Close(); err != nil {
            panic(err)
        }
    }()


	wW := bufio.NewWriter(foW)

	//buf := make([]Privkey, 1024)


	marshed,_ := json.Marshal(N.Bytes())
	marshed = append(marshed, '\n')
	if _, err := wW.Write(marshed); err != nil {
            panic(err)
        }

	marshed,_ = json.Marshal(g.Bytes())
	marshed = append(marshed, '\n')
	if _, err = wW.Write(marshed); err != nil {
            panic(err)
        }


	for i:=0;i<len(Ws);i++ {
		marshed,_ := json.Marshal(Ws[i].Bytes())
		marshed = append(marshed, '\n')
		if _, err := wW.Write(marshed); err != nil {
            panic(err)
        	}
	}




	//fixme test whether it can find error
	//Ws[12] = new(big.Int).Add(Ws[12], big.NewInt(1))
	//return
	//fmt.Println(V)
	//yp := new(big.Int).Exp(g,new(big.Int).Add(keys[This_SIG].p, keys[This_SIG].q), N)
	barmain := pb.StartNew(NUM).Prefix("verify....")
	var worker = runtime.NumCPU()
	working := worker
	jobs2 := make(chan int, worker)
	dones := make(chan struct{}, worker)
	done := false
	error_record := make([]int,0)
	go addJob(jobs2, NUM)

	for i:=0; i<worker; i++ {
			go doJob2(jobs2, dones,Ws,N,g,V, keys,barmain,MSG, error_record)
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

	for i:=0;i<len(error_record);i++{
		fmt.Println("wrong userid:", i)
	}
	fmt.Println("check finished")

}
