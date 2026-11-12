package plugins

import (
	"math/rand"
	"path"
	"strings"
)

// The maze decides between a file and a directory from the name of the
// requested path: a name with an extension is a file, a name without one is
// a directory.
//
// That heuristic is wrong for the files a Linux administrator reads first:
// /etc/passwd, /etc/shadow, /etc/hosts or /root/.bash_history carry no
// extension. Answering them with a directory listing tells the attacker that
// the host is a decoy before it has read a single line.
//
// The table below lists the paths that are files on a real system, and the
// content they answer with. Every one of them is synthetic: the decoy never
// discloses a file of the host, and the credentials it shows are invented.

// systemFile describes a well known file of the decoy.
type systemFile struct {
	// contentType is the content type of the answer.
	contentType string
	// generator builds the content of the file.
	generator func(r *rand.Rand, fullPath string) string
}

// knownSystemFiles maps the paths that are files on a real system to their
// generator.
//
// The key is the cleaned path: the maze cleans the request path before it
// looks it up.
var knownSystemFiles = map[string]systemFile{
	"/etc/passwd":         {contentType: "text/plain; charset=UTF-8", generator: genSystemPasswd},
	"/etc/shadow":         {contentType: "text/plain; charset=UTF-8", generator: genSystemShadow},
	"/etc/group":          {contentType: "text/plain; charset=UTF-8", generator: genSystemGroup},
	"/etc/gshadow":        {contentType: "text/plain; charset=UTF-8", generator: genSystemShadow},
	"/etc/hosts":          {contentType: "text/plain; charset=UTF-8", generator: genSystemHosts},
	"/etc/issue":          {contentType: "text/plain; charset=UTF-8", generator: genSystemIssue},
	"/etc/issue.net":      {contentType: "text/plain; charset=UTF-8", generator: genSystemIssue},
	"/etc/os-release":     {contentType: "text/plain; charset=UTF-8", generator: genSystemOSRelease},
	"/etc/hostname":       {contentType: "text/plain; charset=UTF-8", generator: genSystemHostname},
	"/etc/resolv.conf":    {contentType: "text/plain; charset=UTF-8", generator: genSystemResolvConf},
	"/etc/motd":           {contentType: "text/plain; charset=UTF-8", generator: genSystemMotd},
	"/etc/crontab":        {contentType: "text/plain; charset=UTF-8", generator: genSystemCrontab},
	"/proc/version":       {contentType: "text/plain; charset=UTF-8", generator: genSystemProcVersion},
	"/proc/self/environ":  {contentType: "text/plain; charset=UTF-8", generator: genSystemEnviron},
	"/root/.bashrc":       {contentType: "text/plain; charset=UTF-8", generator: genSystemBashrc},
	"/root/.bash_history": {contentType: "text/plain; charset=UTF-8", generator: genSystemBashHistory},
	"/root/.ssh/id_rsa":   {contentType: "application/x-pem-file", generator: genSystemPrivateKey},
	"/var/log/auth.log":   {contentType: "text/plain; charset=UTF-8", generator: genSystemAuthLog},
}

// systemDirectories maps a directory to the files it holds on a real system.
//
// The listing of these directories shows the well known files, so that a
// directory listing and a file request agree with each other.
var systemDirectories = map[string][]string{
	"/etc": {
		"passwd", "shadow", "group", "hosts", "hostname", "issue",
		"os-release", "resolv.conf", "crontab", "motd", "ssh",
		"nginx", "apache2", "systemd", "apt", "security",
	},
	"/root": {
		".bashrc", ".bash_history", ".profile", ".ssh", ".bash_logout",
	},
	"/root/.ssh": {
		"id_rsa", "id_rsa.pub", "known_hosts", "authorized_keys", "config",
	},
	"/proc": {
		"version", "cpuinfo", "meminfo", "uptime", "self",
	},
	"/var/log": {
		"auth.log", "syslog", "kern.log", "daemon.log", "nginx", "alternatives.log",
	},
}

// systemFileNames returns the well known files of a directory.
func systemFileNames(directory string) []string {
	names, ok := systemDirectories[directory]
	if !ok {
		return nil
	}

	return names
}

// isSystemFile reports whether the path is one of the well known files.
func isSystemFile(cleanPath string) (systemFile, bool) {
	file, ok := knownSystemFiles[cleanPath]
	return file, ok
}

// --- Generators ---

// genSystemPasswd builds a passwd file.
//
// The accounts are the standard ones of a Debian host, plus the application
// accounts of the decoy. The passwords are not in this file, and the hashes
// of the shadow file are all locked: there is no real credential here.
func genSystemPasswd(r *rand.Rand, fullPath string) string {
	accounts := []string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin",
		"sys:x:3:3:sys:/dev:/usr/sbin/nologin",
		"sync:x:4:65534:sync:/bin:/bin/sync",
		"games:x:5:60:games:/usr/games:/usr/sbin/nologin",
		"man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
		"lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
		"mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
		"news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
		"uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
		"proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
		"list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin",
		"irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin",
		"systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin",
		"sshd:x:105:65534::/run/sshd:/usr/sbin/nologin",
		"messagebus:x:106:113::/nonexistent:/usr/sbin/nologin",
		"deploy:x:1000:1000:Deploy:/home/deploy:/bin/bash",
	}

	return strings.Join(accounts, "\n") + "\n"
}

// genSystemShadow builds a shadow file.
//
// Every password is locked. The file looks like the real one, and holds
// nothing that can be used.
func genSystemShadow(r *rand.Rand, fullPath string) string {
	accounts := []string{
		"root:*:19000:0:99999:7:::",
		"daemon:*:19000:0:99999:7:::",
		"bin:*:19000:0:99999:7:::",
		"sys:*:19000:0:99999:7:::",
		"sync:*:19000:0:99999:7:::",
		"games:*:19000:0:99999:7:::",
		"man:*:19000:0:99999:7:::",
		"lp:*:19000:0:99999:7:::",
		"mail:*:19000:0:99999:7:::",
		"news:*:19000:0:99999:7:::",
		"uucp:*:19000:0:99999:7:::",
		"proxy:*:19000:0:99999:7:::",
		"www-data:*:19000:0:99999:7:::",
		"backup:*:19000:0:99999:7:::",
		"list:*:19000:0:99999:7:::",
		"irc:*:19000:0:99999:7:::",
		"nobody:*:19000:0:99999:7:::",
		"systemd-network:*:19000:0:99999:7:::",
		"sshd:*:19000:0:99999:7:::",
		"messagebus:*:19000:0:99999:7:::",
		"deploy:!:19000:0:99999:7:::",
	}

	return strings.Join(accounts, "\n") + "\n"
}

// genSystemGroup builds a group file.
func genSystemGroup(r *rand.Rand, fullPath string) string {
	groups := []string{
		"root:x:0:",
		"daemon:x:1:",
		"bin:x:2:",
		"sys:x:3:",
		"adm:x:4:syslog,deploy",
		"sudo:x:27:deploy",
		"www-data:x:33:",
		"backup:x:34:",
		"deploy:x:1000:",
		"ssh:x:107:",
		"nogroup:x:65534:",
	}

	return strings.Join(groups, "\n") + "\n"
}

// genSystemHosts builds a hosts file.
func genSystemHosts(r *rand.Rand, fullPath string) string {
	hosts := []string{
		"127.0.0.1\tlocalhost",
		"127.0.1.1\tweb-01.internal.company.com web-01",
		"10.20.30.41\tdb-01.internal.company.com db-01",
		"10.20.30.42\tweb-02.internal.company.com web-02",
		"10.20.30.43\tcache-01.internal.company.com cache-01",
		"",
		"::1\tip6-localhost ip6-loopback",
		"fe00::0\tip6-localnet",
		"ff00::0\tip6-mcastprefix",
		"ff02::1\tip6-allnodes",
		"ff02::2\tip6-allrouters",
	}

	return strings.Join(hosts, "\n") + "\n"
}

// genSystemIssue builds the issue file.
func genSystemIssue(r *rand.Rand, fullPath string) string {
	return "Ubuntu 22.04.3 LTS \\n \\l\n\n"
}

// genSystemOSRelease builds the os-release file.
func genSystemOSRelease(r *rand.Rand, fullPath string) string {
	release := []string{
		"PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"",
		"NAME=\"Ubuntu\"",
		"VERSION_ID=\"22.04\"",
		"VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"",
		"ID=ubuntu",
		"ID_LIKE=debian",
		"VERSION_CODENAME=jammy",
		"UBUNTU_CODENAME=jammy",
		"HOME_URL=\"https://www.ubuntu.com/\"",
		"SUPPORT_URL=\"https://help.ubuntu.com/\"",
		"BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"",
		"PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/privacy-and-policy\"",
		"VERSION_CODENAME=jammy",
	}

	return strings.Join(release, "\n") + "\n"
}

// genSystemHostname builds the hostname file.
func genSystemHostname(r *rand.Rand, fullPath string) string {
	return "web-01\n"
}

// genSystemResolvConf builds the resolver configuration.
func genSystemResolvConf(r *rand.Rand, fullPath string) string {
	resolver := []string{
		"nameserver 10.20.0.53",
		"search internal.company.com",
		"options ndots:5",
	}

	return strings.Join(resolver, "\n") + "\n"
}

// genSystemMotd builds the message of the day.
func genSystemMotd(r *rand.Rand, fullPath string) string {
	return "\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n * Documentation:  https://help.ubuntu.com\n * Management:     https://landscape.canonical.com\n * Support:        https://ubuntu.com/advantage\n\n"
}

// genSystemCrontab builds the system crontab.
func genSystemCrontab(r *rand.Rand, fullPath string) string {
	crontab := []string{
		"SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
		"",
		"# m h dom mon dow user  command",
		"17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly",
		"25 6\t* * *\troot\ttest -x /usr/sbin/anacron || run-parts --report /etc/cron.daily",
		"47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || run-parts --report /etc/cron.weekly",
		"52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || run-parts --report /etc/cron.monthly",
		"*/5 * * * *\tdeploy\tcurl -s http://10.20.30.43:8080/health > /dev/null",
	}

	return strings.Join(crontab, "\n") + "\n"
}

// genSystemProcVersion builds the kernel version.
func genSystemProcVersion(r *rand.Rand, fullPath string) string {
	return "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-051) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n"
}

// genSystemEnviron builds the environment of the process.
//
// The variables are the ones a web application usually carries: they are the
// bait that leads an attacker to the next step.
func genSystemEnviron(r *rand.Rand, fullPath string) string {
	environ := []string{
		"HOME=/root",
		"LOGNAME=root",
		"USER=root",
		"HOME=/home/deploy",
		"LOGNAME=deploy",
		"USER=deploy",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOSTNAME=web-01",
		"TERM=xterm",
		"LANG=en_US.UTF-8",
		"APP_ENV=production",
		"DATABASE_URL=postgres://app:app@10.20.30.41:5432/appdb",
		"REDIS_URL=redis://10.20.30.43:6379/0",
		"SECRET_KEY=3f9a1c7d5e2b8046af1d3c9e7b205a4c8",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	return strings.Join(environ, "\n") + "\n"
}

// genSystemBashrc builds the shell profile of the administrator.
func genSystemBashrc(r *rand.Rand, fullPath string) string {
	bashrc := []string{
		"# ~/.bashrc: executed by bash(1) for non-login shells.",
		"",
		"export LS_OPTIONS='--color=auto'",
		"alias ll='ls -alF'",
		"alias la='ls -A'",
		"alias l='ls -CF'",
		"",
		"export PATH=$PATH:/usr/local/go/bin:/home/deploy/go/bin",
		"export GOPATH=/home/deploy/go",
		"export EDITOR=vim",
		"",
		"# Server keys",
		"export AWS_PROFILE=production",
	}

	return strings.Join(bashrc, "\n") + "\n"
}

// genSystemBashHistory builds the command history of the administrator.
//
// It is the most valuable bait of the decoy: it tells the attacker what the
// administrator does, and it invites him to try the same commands.
func genSystemBashHistory(r *rand.Rand, fullPath string) string {
	history := []string{
		"ls -la",
		"cd /var/www/html",
		"git pull",
		"tail -n 100 /var/log/nginx/access.log",
		"cat /etc/passwd",
		"vim /etc/nginx/sites-available/default",
		"systemctl restart nginx",
		"crontab -l",
		"mysql -u app -p appdb",
		"psql postgresql://app:app@10.20.30.41/appdb",
		"docker ps -a",
		"kubectl get pods -n production",
		"journalctl -u web-01 -n 200",
		"scp backup.tar.gz deploy@10.20.30.42:/tmp/",
		"history | grep -i password",
	}

	return strings.Join(history, "\n") + "\n"
}

// genSystemPrivateKey builds a private key.
//
// The key is a syntactically valid OpenSSH key that protects nothing: the
// attacker can use it, and it leads nowhere.
func genSystemPrivateKey(r *rand.Rand, fullPath string) string {
	var body strings.Builder
	for i := 0; i < 12; i++ {
		const lineLength = 64
		line := make([]byte, lineLength)
		for j := range line {
			line[j] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[r.Intn(64)]
		}
		body.Write(line)
		body.WriteString("\n")
	}

	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
		"QyNTUxOQAAACBHdWJlAHBheWxvYWRAZXhhbXBsZS5jb20AAAAHg" + strings.TrimRight(body.String(), "\n") + "\n" +
		"-----END OPENSSH PRIVATE KEY-----\n"
}

// genSystemAuthLog builds an authentication log.
//
// It shows the failed attempts of an attacker who came before, and the
// address of the administrator.
func genSystemAuthLog(r *rand.Rand, fullPath string) string {
	logs := []string{
		"Jan 12 03:02:11 web-01 sshd[2144]: Server listening on 0.0.0.0 port 22.",
		"Jan 12 03:14:07 web-01 sshd[2481]: Accepted password for deploy from 10.20.30.55 port 51244 ssh2",
		"Jan 12 03:14:08 web-01 sshd[2481]: pam_unix(sshd:session): session opened for user deploy by (uid=0)",
		"Jan 12 03:21:52 web-01 sshd[2502]: Failed password for invalid user admin from 203.0.113.77 port 41222 ssh2",
		"Jan 12 03:21:55 web-01 sshd[2502]: Failed password for invalid user admin from 203.0.113.77 port 41230 ssh2",
		"Jan 12 03:22:03 web-01 sshd[2502]: Invalid user admin from 203.0.113.77",
		"Jan 12 03:31:44 web-01 sudo:  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt update",
		"Jan 12 03:58:20 web-01 cron[2631]: (root) CMD (/usr/local/bin/backup.sh)",
	}

	return strings.Join(logs, "\n") + "\n"
}

// systemFileSize returns the size the listing must announce for a well known
// file of a directory.
func systemFileSize(r *rand.Rand, directory, name string) (string, bool) {
	fullPath := path.Join(directory, name)

	file, ok := knownSystemFiles[fullPath]
	if !ok {
		return "", false
	}

	content := file.generator(rand.New(rand.NewSource(seedFromPath(fullPath))), fullPath)

	return formatSize(len(content)), true
}

// systemFileDescription returns the description of a well known file.
func systemFileDescription(name string) string {
	switch name {
	case "passwd":
		return "System user database"
	case "shadow":
		return "Shadow password database"
	case "hosts":
		return "System host file"
	case "id_rsa":
		return "OpenSSH private key"
	case "auth.log":
		return "Authentication log"
	case "bash_history":
		return "Command history"
	default:
		return ""
	}
}
