#!/usr/bin/env sh

username="level13";
password=$(cat ../../level12/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
