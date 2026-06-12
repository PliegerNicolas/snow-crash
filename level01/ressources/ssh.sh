#!/usr/bin/env sh

username="level01";
password=$(cat ../../level00/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
