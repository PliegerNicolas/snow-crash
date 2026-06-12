#!/usr/bin/env sh

username="level04";
password=$(cat ../../level03/flag);
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
