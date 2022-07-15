#! /usr/bin/python
import pexpect
import csv
import os
import time
import datetime

print("******************")
print(datetime.datetime.now())
print("******************")

input_file = "/opt/pw/runtime/users/oos.log"
output_file = '/tmp/site.log'
reb_log = '/tmp/reb_log_oos.log'
check_log = '/tmp/check_log_oos.log'

def clear_old_files():
    file_list = [input_file, output_file, reb_log]
    i = 0
    while i <= len(file_list):
        for files in file_list:
            if os.path.exists(files):
                os.remove(files)
                break
        i += 1


def get_data():
    open_session = pexpect.spawn("sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@localhost")
    open_session.expect("#", timeout=5)
    open_session.sendline("show accessnodes cws | select oper-data |select lte cell oper-data |select umts cell oper-data | select gsm cell oper-data | tab | csv | exclude InService | exclude Disabled| exclude not-conn| exclude CELL| exclude REFERENCE| exclude PEER| exclude NAME| save oos.log")
    open_session.expect("#", timeout=5)
    open_session.sendline('exit')
    open_session.expect(pexpect.EOF)
    open_session.close()


def check_oos():
    with open(input_file) as input_file1:
        input_file_csv = csv.reader(input_file1, delimiter=',')
        counter = 0
        for node in input_file_csv:
            try:
                counter += 1
                if not node:
                    pass
                elif str(node[1]) == 'connected':
                    counter += 1
                    os.system('echo ' + node[0] + ' >> ' + output_file)
            except IndexError:
                pass
        # print counter
        if os.path.exists(output_file):
            os.system("cat " + output_file)
            print"_________________________________"
            print"Above cws were OOS"
        else:
            print('No nodes were OOS but connected')


def reboot_cell():
    """This funcion reboots cell"""
    with open(output_file) as source_path1:
        source_path_csv = csv.reader(source_path1, delimiter=',')
        open_session = pexpect.spawn("sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@localhost")
        #Adding the limit of 5 nodes reboot at max
        num_rows = 0
        for node in source_path_csv:
            #if num_rows <5:
            num_rows +=1
            if node[0] != None:
                try:
                    reb_cmd = 'accessnode cws ' + node[0] + ' reboot-system'
                    open_session.expect('#', timeout=5)
                    open_session.logfile = open(reb_log, 'a')
                    open_session.sendline(reb_cmd)
                    open_session.expect('Are you sure', timeout=5)
                    open_session.sendline('yes')
                    time.sleep(1)
                    # open_session.expect('#', timeout=5)
                    print node[0] + " >> Rebooted"
                except(pexpect.TIMEOUT,  pexpect.EOF):
                    pass
            else:
                print "5 nodes rebooted till now, can't reboot more than 5 nodes"
                break
        open_session.sendline('exit')
        open_session.expect(pexpect.EOF)
        open_session.close()
        print "_________________________________"
        print "....Above nodes were rebooted...."


def check_status():
    if os.path.exists(check_log):
        os.remove(check_log)
    with open(output_file) as opfile:
        opfile_csv = csv.reader(opfile, delimiter=',')
        open_session = pexpect.spawn("sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@localhost")
        for cws in opfile_csv:
            if cws[0]:
                try:
                    check_cmd = "showall| include " + cws[0]
                    open_session.logfile = open(check_log, 'a')
                    open_session.sendline(check_cmd)
                    open_session.expect('#', timeout=5)
                except(pexpect.TIMEOUT,  pexpect.EOF):
                    pass
        open_session.sendline('exit')
        open_session.expect(pexpect.EOF)
        open_session.close()
        print "Thanks, check the status here>> " + check_log


print "...Checking the OOS nodes please wait..."

#Back up data
if os.path.exists(output_file):
    os.system("cp /tmp/site.log /root/oos/site_`date +%Y%m%d%H%M%S`")
if os.path.exists(reb_log):
    os.system("cp /tmp/reb_log_oos.log /root/oos/reb_log_oos_`date +%Y%m%d%H%M%S`")
if os.path.exists(input_file):
    os.system("cp /opt/pw/runtime/users/oos.log /root/oos/oos_hng_log_`date +%Y%m%d%H%M%S`")


clear_old_files()
get_data()
check_oos()
if os.path.exists(output_file):
    reboot_cell()


print "Logs taken- thanks, quitting now.."



