''' This is a kuberenetes flavored version of the RPC server and monitor. 
The main difference is that we won't try and stop/start the target, 
but rather just wait for kubernetes to bring it back up again.'''


import os
import sys
import time
import signal
import argparse
import threading
import subprocess
from boofuzz import pedrpc

'''
This is a base monitor class, don't instantiate it.
'''
class TargetMonitor():
    def __init__(self, binary_path):
        self.pid = None
        self.binary_path = binary_path
        self.pid = self.getpid(self.binary_path)
        self.should_exit = False
        self.attach(self.pid)
        signal.signal(signal.SIGINT, self.signal_handler)

    '''
    Checks if the target is alive. 
    You might want to redefine this function.
    '''
    def is_target_alive(self, timeout):
        try:
            time.sleep(timeout)
            os.kill(self.pid, 0)
        except OSError:
            return False
        return True


    def reset_target(self, timeout):
        return self.getpid(self.binary_path)


    def attach(self, pid):
        threading.Thread(target=self.monitor_loop).start()
        print('Attached to [%s] -> %s' % (self.pid, self.binary_path))


    '''
    Gets a PID of the target. 
    You might want to redefine this function.
    '''
    def getpid(self, binary_path):
        pid = None

        try:
            output = subprocess.check_output(('pidof', binary_path)).decode().replace('\n', '')
            pid = int(output)
        except:
            pass

        return pid




    '''
    A loop that checks whether the target is alive.
    For a kubernet cluster, we will not try and stop/start the target, but rather just wait 
    for kubernetes to bring it back up again
    You might want to redefine this function.
    '''
    def monitor_loop(self):
        while self.is_target_alive(0) == True:
            pass

        if self.should_exit == True:
            return
        print('The target is dead!')
        #self.pid = self.reset_target(5)
        os.system('sleep 5')
        self.pid = self.getpid(self.binary_path)
        self.attach(self.pid)

    def signal_handler(self, signal, frame):
        try:
            self.should_exit = True
            self.stop_target()
        finally:
            sys.exit(-1)

    '''
    Stops the target. For kubernetes, we will not try and stop the target, but rather just wait for kubernetes to bring it back up again
    Implement this function in a subclass.
    '''
    def stop_target(self):
        pass

    '''
    Starts the target. For kubernetes, we will not try and start the target, but rather just wait for kubernetes to bring it back up again
    Implement this function in a subclass.
    '''
    def start_target(self):
        pass

'''
This is the monitor class that is specific to FRRouting.

NOTE: this has been tested on Ubuntu 22.04, make sure to redefine the
stop_target() and start_target() functions to reflect your environment.
'''
class FRRMonitor(TargetMonitor):
    def __init__(self, binary_path='/usr/lib/frr/bgpd'):
        super().__init__(binary_path)

    '''Stops the target. For kubernetes, we will not try and stop the target, but rather just wait for kubernetes to bring it back up again'''
    def stop_target(self):
        pass

    '''Starts the target. For kubernetes, we will not try and start the target, but rather just wait for kubernetes to bring it back up again'''
    def start_target(self):
        pass


    def is_target_alive(self, timeout):
        pid = None
        try:
            time.sleep(timeout)
            output = None
            command = ['pgrep', '-f', self.binary_path]
            output = subprocess.check_output(command)
            ''' For kubernetes, we tend to get multiple PIDs, so we will just check if there are any PIDs returned, 
            rather than trying to convert it to an int. Having the integer allows for stoping
            But we won't try and do that in kuberenetes, since we will just wait for kubernetes to restart the target'''
            #pid = int(output)
            pid = output

        except:
            print("Exception in is_target_alive", output)

        print("Returning is_target_alive:", pid)
        if pid == None:
            return False
        else:
            return True

'''
This is the monitor class that is specific to EXABGP.


'''
class EXAMonitor(TargetMonitor):
    ''' Note the name of the binary where exabgp is running including the config file. Trying to be as specific as possible
    since there might be multiple processes with python3 in the name, and we want to make sure we are checking the right one'''

    def __init__(self, binary_path='/usr/bin/python3 /usr/local/bin/exabgp /data/exabgp.ini'):
        super().__init__(binary_path)

    def stop_target(self):
        pass

    def start_target(self):
        pass

    def is_target_alive(self, timeout):
        pid = None
        try:
            time.sleep(timeout)
            output = None
            command = ['pgrep', '-f', self.binary_path]
            print("Command:", command)
            output = subprocess.check_output(command)
            pid = output
        except:
            print("Exception in is_target_alive", output)
        print("Returning is_target_alive:", pid)
        if pid == None:
            return False
        else:
            return True



'''
This is a very simple RPC server for letting the fuzzer know that the target is down.
'''
class RPCServer(pedrpc.Server):
    def __init__(self, monitor, host, port):
        super().__init__(host, port)
        self.monitor = monitor

    def is_target_alive(self, timeout=0):
        return self.monitor.is_target_alive(timeout)

    def receive_testcase(self, test_suite, index, payload):    
        print('\nPotential crash: [%s -> %s]' % (test_suite, index))    
        print(payload)    
        print('\n')  

if __name__ == '__main__':
    ''' need to bring these values in from environment variables or command line arguments'''

    monitor = 'frr'
    port = 1234
    host = '0.0.0.0'
    if monitor == 'frr':
        monitor = FRRMonitor() 
    elif monitor == 'exa':
        monitor = EXAMonitor() 
    else:
        print('The monitor \'%s\' is not supported!')
        sys.exit(-1)

    rpc_server = RPCServer(monitor=monitor, host=host, port=port)
    rpc_server.serve_forever()