#!/usr/bin/env sh

username="level12";
password=$(cat ../../level11/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
