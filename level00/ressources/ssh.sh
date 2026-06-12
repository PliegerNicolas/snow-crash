#!/usr/bin/env sh

username="level00";
password="level00";
host="localhost";
port="4242";

sshpass -p "$password" ssh $username@$host -p "$port";
