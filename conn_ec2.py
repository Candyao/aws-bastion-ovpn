import paramiko
import configparser
import sys

conf=configparser.ConfigParser()
conf.read('config.ini')

cmd_str="""yum install -y gcc python37 openldap-devel python3-devel && pip3 install python-ldap
scp -r -o StrictHostKeyChecking=no -i key.pem ec2-user@Host:@script_dir/remote_file .
cd remote_file && chmod +x paramiko_create_ldap.py && ./paramiko_create_ldap.py
touch @user_context && touch @vpn
[ -f @user_context ] && scp -r -i ../key.pem user_context ec2-user@Host:~
[ -f @vpn ] && scp -r -i ../key.pem @vpn ec2-user@Host:~"""

def read_file(file):
    with open(file,'r') as f:
        lines=f.read()
    return lines

def paramiko_trans(host):
    pkey = paramiko.RSAKey.from_private_key_file('/root/.ssh/id_rsa')
    trans = paramiko.Transport((host, 22))
    trans.start_client()
    trans.auth_publickey(username="root", key=pkey)
    return trans

def paramiko_channel(trans):
    channel = trans.open_session()
    channel.settimeout(7200)
    channel.get_pty()
    channel.invoke_shell()
    return channel

def run_cmd(channel,cmd):
    channel.send(cmd)
    rst=b""
    while True:
       buffer = channel.recv(1)
       if '\r' not in rst.decode('utf-8','ignore'):
          rst+=buffer
       elif 'END 1' in rst.decode('utf-8','ignore'):
          break
       else:
          print (rst.decode('utf-8','ignore').strip())
          rst=b""

def paramiko_cmd_format(str):
    end_str=' && ls /etc/paramiko \r'
    return str+end_str

if __name__ == '__main__':
    Work_dir=sys.argv[1]
    Script_dir=Work_dir+"/python_ssh/"
    Host=conf.get('COMMON','HOST')
    Remote_host=conf.get('COMMON','REMOTE_HOST')
    Key_name=conf.get('COMMON','KEY_NAME')
    Trans=paramiko_trans(Remote_host)
    Channel=paramiko_channel(Trans)
    End_flag=paramiko_cmd_format("mkdir -p /etc/paramiko && touch /etc/paramiko/END\ {0..1} ")
    run_cmd(Channel,End_flag)
    file_key=read_file(Script_dir+Key_name)
    put_key=paramiko_cmd_format("echo '%s' > key.pem && chmod 600 key.pem") % (file_key)
    run_cmd(Channel, put_key)
    cmd_str=cmd_str.replace('@Host','@'+Host).replace('@script_dir',Script_dir).\
        replace('@vpn',sys.argv[2]+"-vpn.ovpn").replace('@user_context',sys.argv[2]+"_user_context")
    for i in cmd_str.split('\n'):
        cmd=paramiko_cmd_format(i)
        run_cmd(Channel, cmd)
    Channel.close()
    Trans.close()