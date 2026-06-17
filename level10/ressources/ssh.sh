#!/usr/bin/env sh

username="level10";
password=$(cat ../../level09/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
