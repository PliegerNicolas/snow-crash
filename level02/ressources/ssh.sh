#!/usr/bin/env sh

username="level02";
password=$(cat ../../level01/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
