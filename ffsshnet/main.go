package main

import (
	"ffsshnet/ff_ssh"
	"fmt"
	"strings"
	"sync"

)

func filterResult(result, firstCmd ,ip string) string {
	//对结果进行处理，截取出指令后的部分

	filteredResult := "---------------------------"+ip+"-----------------------------\n"+""
	resultArray := strings.Split(result, "\n")
	findCmd := false
	promptStr := ""
	for _, resultItem := range resultArray {
		resultItem = strings.Replace(resultItem, " \b", "", -1)
		if findCmd && (promptStr == "" || strings.Replace(resultItem, promptStr, "", -1) != "") {
			filteredResult += resultItem + "\n"
			continue
		}
		cmd1  := strings.Split(firstCmd,"\r")
		for _,firstCmd:=range cmd1 {
			if strings.Contains(resultItem, firstCmd) {
				findCmd = true
				promptStr = resultItem[0:strings.Index(resultItem, firstCmd)]
				promptStr = strings.Replace(promptStr, "\r", "", -1)
				promptStr = strings.TrimSpace(promptStr)

				//将命令添加到结果中
				filteredResult += resultItem + "\n"
			}
		}

	}

	if !findCmd {
		return result
	}

	return filteredResult
}

func ffssh(ip string, waitgroup *sync.WaitGroup)string{
	cmd := "sys\rvlan 100\rint vlan 100\rip add 192.1.1.1 24\rdis ip int b"
	output:= ff_ssh.SSH_run("fanchao", "1qaz9ol.", ip, "", 22, []string{}, cmd)
	//fmt.Printf("============================%s=============================\n",ip)
	//fmt.Printf("%v\n",filterResult(output,cmd,ip))
    //return filterResult(output, cmd)

    defer waitgroup.Done()
	return filterResult(output, cmd ,ip)

    }


//加管道的配置
func main() {
	var ch chan string
	ch = make(chan string,1000)
	var wg sync.WaitGroup
	path := "/Users/ffadmin/ffstudy/studygo/src/ffsshnet/fanfan.txt"
	iplist := ff_ssh.Readline(path)
	wg.Add(len(iplist))
	for _, ip := range iplist {
		go func(ip string,waitgroup *sync.WaitGroup,ch chan string) {
			c:= ffssh(ip, &wg)
			ch<-c

		}(ip,&wg,ch)
		}
	wg.Wait()

    close(ch)

	for data := range ch{
		fmt.Printf("%v",data)
	}

	fmt.Printf("====================================end==================================\n")


}


