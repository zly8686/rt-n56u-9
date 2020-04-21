#!/bin/sh

TRIGS="pdv-7621-ci pdv-7628-ci"

git config --global user.name "hanwckf"
git config --global user.email "my375229675@gmail.com"

gitver="$(git rev-parse --short=7 HEAD 2>/dev/null)"
msg="build trigger: $gitver"

for repo in $TRIGS ; do
	cd /opt
	if [ -f /opt/${repo}.yml ]; then
		git clone --depth=1 https://hanwckf:$GITHUB_KEY@github.com/hanwckf/$repo.git && cd $repo
		echo "$(LANG=C date) $gitver" >> Build.log
		cp -f /opt/${repo}.yml .travis.yml
		git add .
		git commit -m "$msg"
		git remote set-url origin https://hanwckf:$GITHUB_KEY@github.com/hanwckf/$repo.git
		git push
	fi
done
