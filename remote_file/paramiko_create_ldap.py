import ldap
from ldap import modlist
import configparser
import random
import string
import hashlib
import base64
import struct
import shlex
import subprocess
import time

totle_string = string.ascii_letters + string.digits
conf=configparser.ConfigParser()
conf.read("config.ini")

env_str = """
           yum -y install docker &&
           systemctl start docker &&
           docker pull wheelybird/openvpn-ldap-otp:v1.4 &&
           docker run \
           --name openvpn \
           --privileged \
           --volume /path/on/host:/etc/openvpn \
           --detach=true \
           -p 1194:1194 \
           -e '"OVPN_SERVER_CN=%s"' \
           -e '"LDAP_URI=%s"' \
           -e '"LDAP_BASE_DN=%s"' \
           -e '"LDAP_BIND_USER_DN=%s"' \
           -e '"LDAP_BIND_USER_PASS=%s"' \
           -e '"OVPN_PROTOCOL=tcp"' \
           -e '"ENABLE_OTP=true"' \
           -e '"LDAP_TLS_VALIDATE_CERT=false"' \
           -e '"OVPN_ROUTES=%s"' \
           --cap-add=NET_ADMIN \
           wheelybird/openvpn-ldap-otp:v1.4
        """% (conf.get('Open_Vpn','OVPN_SERVER_CN'),conf.get('COMMON','AUTH_LDAP_SERVER_URI'),
               conf.get('COMMON','AUTH_LDAP_BASE_DN'),conf.get('COMMON','AUTH_LDAP_BIND_DN'),
               conf.get('COMMON','AUTH_LDAP_BIND_PASSWORD'),conf.get('Open_Vpn','OVPN_ROUTES'))

ovpn_client_conf="""
                 docker exec openvpn show-client-config
                 """
ovpn_client_write="""
                 echo "route %s vpn_gateway" >> @vpn.ovpn &&
                 echo "route-metric 50" >> @vpn.ovpn &&
                 echo "route-nopull" >> @vpn.ovpn
                  """ % (conf.get('Open_Vpn','OVPN_ROUTES'))

user_context="""
VPN配置指引：

1 点击链接下载配置文件：%s

2 导入配置文件，mac电脑推荐使用tunnelblick客户端，windows电脑推荐openvpn客户端；

3 连接vpn链路，输入用户名，密码（密码=密码串+动态验证码，例如：密码串是abcd,动态验证码是123456，那么vpn密码即是abcd123456）；

4 请不要将个人的用户名密码透露给其他人，以免造成不必要的损失；

用户名：{}

密码串：{}

谷歌验证码信息： 

{}
------------------------------------------------------------------------------------------------------------
""" % (conf.get('Oss_Dir','oss'))

def get_otp_cmd(user):
    otp_str="docker exec openvpn add-otp-user %s | grep https://" % user
    return otp_str

def print_message(process,user=None,passwd=None):
    while process.poll() is None:
        line = process.stdout.readline()
        line = line.strip()
        if line and user is not None:
            with open(conf.get('COMMON','SYSTEM_NAME')+'_user_context',"a") as f:
                f.write(user_context.format(user,passwd,line.decode()))
            print('Subprogram output: [user:{},url:{}]'.format(user,line.decode()))
        elif line and user is None:
            print('Subprogram output: [{}]'.format(line.decode()))
    if process.returncode == 0:
        print('Subprogram success')
    else:
        print('Subprogram failed error: %s' % process.stderr.read().decode())

def format_cmd(str):
    str_cmd=shlex.split(str)
    str_cmd=" ".join(str_cmd)
    return str_cmd

def run_cmd(cmd):
    p=subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    return p

def get_md5(s):
    m = hashlib.md5(s)
    return m.hexdigest()

def convert_md5(origin):
    result = []
    s = ""
    for i in range(len(origin)):
        s += origin[i]
        if i %2 != 0 :
            int_hex = int(s, 16)
            result.append(int_hex)
            s = ""
    return result

def strcut_pack(md5_l):
    c=b''
    for i in md5_l:
        pck=struct.pack("B",i)
        c+=pck
    return c

def user_passwd():
    passwd=get_passwd(8)
    md5_str=get_md5(passwd.encode())
    md5_list=convert_md5(md5_str)
    pack_bytes=strcut_pack(md5_list)
    return [passwd,"{MD5}"+base64.b64encode(pack_bytes).decode()]

def get_passwd(num):
    res = ''.join(random.sample(totle_string, num))
    return res

def get_conn():
    ldapconn = ldap.initialize(conf.get("COMMON", "AUTH_LDAP_SERVER_URI"),bytes_mode=False)
    ldapconn.protocol_version = ldap.VERSION3
    ldapconn.simple_bind_s(conf.get("COMMON", "AUTH_LDAP_BIND_DN"), conf.get("COMMON", "AUTH_LDAP_BIND_PASSWORD"))
    return ldapconn

def create_ou(OU,conn):
    dn = "ou=%s," % OU + conf.get("COMMON", "AUTH_LDAP_BASE_DN")
    attrs={}
    attrs['objectclass'] = [b'organizationalUnit', b'top']
    ldif = modlist.addModlist(attrs)
    try:
        res = conn.add_s(dn, ldif)
        if res[0] == 105:
            print("CREATE ou=%s SUCCESS" % OU)
    except ldap.ALREADY_EXISTS as _:
        print("OU ou=%s ALREADY EXISTS" % OU)

class Create_Group():
   def __init__(self,cn,ou):
       self.cn=cn
       self.ou=ou

   def create_group(self,conn,group_id):
       dn="cn=%s," % self.cn + "ou=%s," % self.ou + conf.get("COMMON","AUTH_LDAP_BASE_DN")
       attrs ={}
       attrs['gidnumber']=group_id.encode('utf-8')
       attrs['objectclass']=[b'top',b'posixGroup']
       ldif = modlist.addModlist(attrs)
       try:
           res = conn.add_s(dn, ldif)
           if res[0] == 105:
               print("CREATE GROUP %s of ou=%s SUCCESS" % (self.cn,self.ou))
       except ldap.ALREADY_EXISTS as _:
           print("GROUP %s of ou=%s ALREADY EXISTS" % (self.cn,self.ou))

class Create_People():
   def __init__(self,cn,ou,g_cn,g_ou,conn):
       self.cn=cn
       self.ou=ou
       self.conn=conn
       self.g_cn=g_cn
       self.g_ou=g_ou

   def search_gorup_num(self):
       searchScope = ldap.SCOPE_SUBTREE
       searchFilter = 'cn=%s' % (self.g_cn)
       base_dn = "ou=%s," % (self.g_ou) + conf.get("COMMON", "AUTH_LDAP_BASE_DN")
       res = self.conn.search_s(base_dn, searchScope, searchFilter, None)
       if len(res) == 0:
           print('not found')
       else:
           res_gid_num=res[0][1]['gidNumber'][0].decode('utf-8')
           return res_gid_num

   def create_people(self,u_id,gid,passwd):
       dn="cn=%s," % self.cn + "ou=%s," % self.ou + conf.get("COMMON","AUTH_LDAP_BASE_DN")
       attrs ={}
       attrs['gidnumber']= gid.encode()
       attrs['givenname']=self.cn.split()[0].encode()
       attrs['objectclass']=[b'top',b'posixAccount',b'inetOrgPerson']
       attrs['sn']=self.cn.split()[1].encode()
       attrs['uid']=(self.cn[0]+self.cn.split()[1]).encode()
       attrs['uidnumber']=u_id.encode()
       attrs['userpassword']=passwd[1].encode()
       attrs['homedirectory']=("/home/user/"+self.cn[0]+self.cn.split()[1]).encode()
       ldif = modlist.addModlist(attrs)
       try:
           res = self.conn.add_s(dn, ldif)
           if res[0] == 105:
               print("CREATE USER %s of ou=%s SUCCESS" % (self.cn,self.ou))
       except ldap.ALREADY_EXISTS as _:
           print("USER %s of ou=%s ALREADY EXISTS" % (self.cn,self.ou))
           user_exits.append(attrs['uid'].decode())
       return user_exits

def check_step(step):
    step=str(step)
    if step in conf.get("Step",'step'):
        return True
    else:
        return False

def main():
    if check_step(0) or check_step(1):
        conn_ldap=get_conn()
        print("\n##########################create ldap OU#####################################\n")
        OrganizationUnit = conf.options("OU")
        for var in OrganizationUnit:
            create_ou(conf.get("OU", var), conn_ldap)
        Groups = conf.options("OU_Group_group")
        group_ID = conf.get("COMMON", "BASE_GROUP_ID")
        print("\n####################create ldap group #######################################\n")
        for grp in Groups:
            creategroup = Create_Group(cn=conf.get("OU_Group_group", grp), ou=conf.get("OU", "Group"))
            creategroup.create_group(conn_ldap, group_ID)
            group_ID = int(group_ID)
            group_ID += 1
            group_ID = str(group_ID)
        print("\n####################create ldap user #######################################\n")
        # UserDisable = conf.options('OU_People_Disabled_User')
        # for user in UserDisable:
        #     createpeople = Create_People(cn=conf.get("OU_People_Disabled_User", user), ou=conf.get("OU", "People"),g_cn=conf.get("OU_Group_group", "disabled"), g_ou=conf.get("OU", "Group"),conn=conn_ldap)
        #     gidnum = createpeople.search_gorup_num()
        #     pass_wd = user_passwd()
        #     User_Disable_Dict = {}
        #     createpeople.create_people(u_id=U_ID, gid=gidnum, passwd=pass_wd)
        #     U_ID = int(U_ID)
        #     U_ID += 1
        #     U_ID = str(U_ID)
        UserAction = conf.options('OU_People_Action_User')
        U_ID = conf.get("COMMON", "BASE_UID_NUMBER")
        for user in UserAction:
            createpeople = Create_People(cn=conf.get("OU_People_Action_User", user), ou=conf.get("OU", "People"),
                                         g_cn=conf.get("OU_Group_group", "action"), g_ou=conf.get("OU", "Group"),
                                         conn=conn_ldap)
            gidnum = createpeople.search_gorup_num()
            pass_wd = user_passwd()
            createpeople.create_people(u_id=U_ID, gid=gidnum, passwd=pass_wd)
            User_Action_Dict[user] = pass_wd
            U_ID = int(U_ID)
            U_ID += 1
            U_ID = str(U_ID)
    if check_step(0):
        print("\n############# install docker and start openvpn  #######################\n")
        env_cmd = format_cmd(env_str)
        p = run_cmd(env_cmd)
        print_message(p)
        p.wait()
        print("\n##############   add otp user               #############################\n")
        otp_user = dict(conf.items('OU_People_Action_User'))
        for k, v in otp_user.items():
            user = v[0] + v.split()[1]
            if user in user_exits:
                pass
            else:
                otp_cmd = get_otp_cmd(user)
                p = run_cmd(otp_cmd)
                print_message(process=p, user=user, passwd=User_Action_Dict[k][0])
                p.wait()
        print("\n##############   get openvpn client config   ############################\n")
        for i in range(10):
            client_conf_cmd = format_cmd(ovpn_client_conf)
            p = run_cmd(client_conf_cmd)
            stdout,stderr=p.communicate()
            result=stdout.decode()
            if result:
                print (result)
                with open(conf.get('COMMON','SYSTEM_NAME')+'-vpn.ovpn', 'w') as f:
                    f.write(result)
                break
            else:
                print("waiting for client config init")
                time.sleep(30)

        write_ovpn_cmd=format_cmd(ovpn_client_write.replace('@vpn.ovpn',conf.get('COMMON','SYSTEM_NAME')+'-vpn.ovpn'))
        p = run_cmd(write_ovpn_cmd)
        print_message(p)
        p.wait()

if __name__ == '__main__':
    user_exits = []
    User_Action_Dict={}
    # User_Disable_Dict={}
    main()