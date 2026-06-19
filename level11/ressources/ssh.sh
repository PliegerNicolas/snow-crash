#!/usr/bin/env sh

username="level11";
password=$(cat ../../level10/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
