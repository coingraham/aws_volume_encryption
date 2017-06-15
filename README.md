# aws_volume_encryption

Utility for quickly encrypting the root drives of an array of systems.  

## WARNING

I'm still researching the impact of encrypting the root volume on the product billing metadata.  This could potentially negatively impact marketplace AMIs or licensed OS AMIs like RHEL.

## Getting Started

Clone the repo, edit the configuration file and run the script.  There are no arguments.

### Prerequisites

In order for the script to function you'll need python 2.7 and the following python modules

```
boto3
botocore
multiprocessing
```

## Built With

* [Boto3](http://boto3.readthedocs.io/en/latest/index.html) - The AWS Python SDK Used.

## Authors

* **[CoinGraham](https://github.com/CoinGraham)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Forked from [dwbelliston](https://github.com/dwbelliston/aws_volume_encryption) and updated for mass encryption of systems.


