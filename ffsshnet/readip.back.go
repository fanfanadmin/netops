package main

import (
	"fmt"
	"os"
	"bufio"
	"io"
	"strings"

)




func Readline(path string)([]string){
	s := make([]string,0)
	f,err := os.Open(path)
	if err != nil{
		fmt.Printf("err",err)

	}
	defer f.Close()
	r := bufio.NewReader(f)

	for {
		buf ,err := r.ReadBytes('\n',)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Printf("err", err)
		}
		str := string(buf)
		newstr := strings.Trim(str,"\n")
		s = append(s,newstr)

	}
	return s



}
/*
func Sshswitch(ip interface{},ch chan interface{}){
	fmt.Printf("ssh@%v\n", ip)
	ch <- ip
}


func main() {

	ch := make(chan interface{})
	path := "/Users/ffadmin/ffstudy/studygo/src/ffsshnet/fanfan.txt"
	news := Readline(path)
	var i int
	for i = 0; i < len(news)-1; i++ {
		go Sshswitch(news[i], ch)
	}
	for i = 0; i < len(news)-1; i++ {
		fmt.Printf("%v\n执行完毕\n", <-ch)
	}
	//runtime.Gosched() //让出时间片，先让别的协议执行，它执行完，再回来执行此协程
	time.Sleep(time.Second * 5)


}
*/
