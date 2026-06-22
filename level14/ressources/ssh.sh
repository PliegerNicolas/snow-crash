#!/usr/bin/env sh

username="level14";
password=$(cat ../../level13/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
