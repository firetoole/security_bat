## Security Bat

This tool is designed to take a quick look at your Mac endpoint and score it based on a number of best practices, and indicators of weak security posture. This data is then sent up to a server (or stored locally) to be scored based on an average of all endpoints that report in.

**Scoring**
![scale.png](https://github.com/artsturdevant/security_bat/blob/master/scale.png?raw=true)


## Installation

**Endpoint**

There are a few components to this project pull down the reopo to wherever and run ```setup.sh```
this should setup a virtualenv and pip install all needed libraries.

**test framework**
We have included a bunch of stuff already, but feel free to add in your own in [security_bat](https://github.com/artsturdevant/security_bat/blob/master/security_bat.py)
They should just be a python methods and return true / false and other data into the master dictionary (if you want)

```def get_useful_data(self):
        """

        :return: dict with some useful data
        """

        # Just do something
        do something that you care about here and collect very_useful_data

        # Store useful data that you care about here
        self.master_dict.update({'usful_data': very_useful_data})

        return True```


**Docker image**
this is a base server that you can run to collect the endpoint data and do fancy things with graphs
TO BE RELEASED LATER (***I promise we made this! it's just not ready yet***)

## Usage
Once installed on the endpoint the python app can be called with no flags and all tests will be run. Or you can specify flags individually so that only those tests run.

security_bot.py -flag

## Tests



Describe and show how to run the tests with code examples.

## License

A short snippet describing the license (MIT, Apache, etc.)