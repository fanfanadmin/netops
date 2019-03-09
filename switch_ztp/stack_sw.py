#! /usr/bin/env python
#  -*- coding: utf-8 -*-
# __author__  =  "ffadmin"
import time
import ops
import re

def panduan_stack():
    opsObj = ops.ops()
    handle, err_desp= opsObj.cli.open()
    command_output = opsObj.cli.execute(handle, "dis sn all | in /0/6")
    format_command_output=list(command_output)[0]
    result = "Copper" in re.split(r'[-\r\n\s'']''*\s*-*',format_command_output)[-2]
    opsObj.cli.close(handle)
    return result

def auto_config():
    opsObj = ops.ops()
    handle, err_desp= opsObj.cli.open()
    choice = {"Continue": "y", "save": "y"}
    opsObj.cli.execute(handle, "delete flash:/stack_sw.py",choice)
    opsObj.cli.close(handle)

	
def auto_stack():
    opsObj = ops.ops()
    handle, err_desp= opsObj.cli.open()
    choice = {"Continue": "y", "save": "y"}
    c = opsObj.cli.execute(handle,"dis cu | in device board")
    member = c[0].split(' ')[2]
    opsObj.cli.execute(handle,"system-view immediately ")
    opsObj.cli.execute(handle,"stack ")
    opsObj.cli.execute(handle, "stack member %s domain 30" % member)
    if member == "1":
        opsObj.cli.execute(handle, "stack member %s priority 200 " % member)
    opsObj.cli.execute(handle,"int stack-port %s/1"%member)
    opsObj.cli.execute(handle,"port member-group interface 40G %s/0/5 to %s/0/6"%(member,member),choice)
    opsObj.cli.execute(handle, "quit")
    opsObj.cli.execute(handle, "quit")
    opsObj.cli.execute(handle, "delete flash:/stack_sw.py",choice)
    opsObj.cli.close(handle)
	
	
def main():
    if panduan_stack():
        auto_stack()
    else:
        auto_config()

		
if __name__ == "__main__":
    main()
