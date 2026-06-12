#!/usr/bin/env sh

username="level03";
password=$(cat ../../level02/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
