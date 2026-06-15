#!/usr/bin/env sh

username="level09";
password=$(cat ../../level08/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
