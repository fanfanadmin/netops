package ff_ssh

import (
	"fmt"
	"os"
	"bufio"
	"io"
	"strings"

)




func Readline(path string)([]string) {
	s := make([]string, 0)
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("err", err)

	}
	defer f.Close()
	r := bufio.NewReader(f)

	for {
		buf, err := r.ReadBytes('\n', )
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Printf("err", err)
		}
		str := string(buf)
		newstr := strings.Trim(str, "\n")
		s = append(s, newstr)

	}
	return s

}