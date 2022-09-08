# Exercise 2

Create Dockerfile for building image for the getweather program you’ve written.
Then build and run the image

# 2.1 Write a network scanner

## Prerequisites:

### Install click library 

```python
$ pip install click
```

## Usage:
### For help run:
```
$ python scanner.py --help
```
### To use scanner run :

```
$ python scanner.py 10.1.1.1
```

### Default starting port is 1 and ending is 500, to run with different ports use --s and --e :
### Scan from port 1 to 20
```
$ python scanner.py 10.1.1.1 --e 20
```

### Scan from port 20 to 500
```
$ python scanner.py 10.1.1.1 --s 20
`
```

### Scan from port x to y
```
$ python scanner.py 10.1.1.1 --s x --e y
```


# 2.2 Kubernetize and deploy the scanner


## apply manifest :
```
$ kubectl apply -f scanner.yaml
```
## get cron jobs
```
$ kubectl get cj
```