# rhttp

auth none
socks -p5959

auth none
proxy -p5858

users test:CL:tset
allow test
auth strong
socks -p5757
