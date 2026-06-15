#!/usr/bin/env sh

username="level08";
password=$(cat ../../level07/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
