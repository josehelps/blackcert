#!/usr/bin/env python3

import configparser
import logging
import os
import sys
import time
import certstream
import argparse
import json
import datetime
import requests
import math
import yaml
import re
from Levenshtein import distance
from tld import get_tld
from pathlib import Path
from modules.confusables import unconfuse


VERSION = '1'


def setup_logging(LOG_PATH,LOG_LEVEL):
    """Creates a shared logging object for the application"""
    # create logging object
    logger = logging.getLogger('blackcert')
    logger.setLevel(LOG_LEVEL)
    # create a file and console handler
    fh = logging.FileHandler(LOG_PATH)
    fh.setLevel(LOG_LEVEL)
    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)
    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

# shamelessly stolen from https://github.com/x0rz/phishing_catcher/blob/master/catch_phishing.py
# credits to @x0rz

def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def score_domain(domain):
    """Score `domain`.
    The highest score, the most probable `domain` is a phishing site.
    Args:
        domain (str): the domain to check.
    Returns:
        int: the score of `domain`.
    """

    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 20

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass

    # Higer entropy is kind of suspicious
    score += int(round(entropy(domain)*10))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # ie. detect fake .com (ie. *.com-account-management.info)
    if words_in_domain[0] in ['com', 'net', 'org']:
        score += 10

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score

def parse_configs(CONFIG_PATH):
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    settings = {}

    for section in config.sections():
        for key in config[section]:
            try:
                settings[key] = perform_lookup(key, config.get(section, key))
            except Exception as e:
                print("ERROR - with configuration file at {0} failed with error {1}".format(CONFIG_PATH, e))
                sys.exit(1)
    return settings


def perform_lookup(config_key, config_value):
    if config_key == 'keywords':
        keywords = [e.strip() for e in config_value.split(',')]
        return keywords
    else:
        return config_value


def process_message(domain, message):
    result = {}
    result['timestamp'] = str(datetime.datetime.utcnow().isoformat())
    result['fingerprint'] = message['data']['leaf_cert']['fingerprint'].replace(":", "").lower()
    result['domain'] = domain
    result['subject'] = message['data']['leaf_cert']['subject']['aggregated']
    result['CA'] = [c['subject']['CN'] for c in message['data']['chain']]
    return result


def sendslack(slackhook, domain, result):
    """Send message to Slack"""

    slack_data = {"blocks": [{"type": "section",
                              "text": {"type": "mrkdwn", "text":":lock_with_ink_pen: :oncoming_police_car: :zap: *Certificate changes have been detected for: {0}*\n see details in *<https://crt.sh/?q={1}|crt.sh>* :flashlight:".format(domain, result['fingerprint'])}},
                             {"type": "section", "fields": [{"type": "mrkdwn","text": "*Domain:*\n{0}".format(domain)},
                                                            {"type": "mrkdwn", "text": "*Score:*\n {0}".format(result['score'])},
                                                            {"type": "mrkdwn","text": "*CA:*\n{0}".format(result['CA'])},
                                                            {"type": "mrkdwn","text":"*Subject Line:*\n{0}".format(result['subject'])}]},
                             {"type": "context", "elements": [{"type": "mrkdwn", "text": "*Author:* <https://github.com/d1vious/blackcert|blackcert>"}]}]}

    response = requests.post(
        slackhook, data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )

    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text))

def write_results(result):
    try:
        with open(OUTPUT_PATH, 'a') as outfile:
            json.dump(result, outfile)
    except Exection as e:
        log.error("writing result file: {0}".format(str(e)))


def callback(message, context):
    #log.info("Message -> {}".format(message))
    keywords = config['keywords']
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        
        for domain in all_domains:
            for keyword in keywords:
                if domain.find(keyword) != -1:
                    result = process_message(domain, message)
                    score = score_domain(domain)
                    log.info("matched domain: {0} for keyword: {1} score: {2}".format(domain, keyword, score))
                    result['score'] = score
                    # only high scores we alert on
                    if result['score'] >= int(config['alert_score_threshold']):
                        log.info("slack alert score threshold reached for domain: {0} with score: {2}".format(domain, keyword, score))
                        sendslack(config['hook'], domain, result)
                    write_results(result)

def on_open(instance):
    # Instance is the CertStreamClient instance that was opened
    print("Connection successfully established!")

def on_error(instance, exception):
    # Instance is the CertStreamClient instance that barfed
    print("Exception in CertStreamClient! -> {0}".format(exception))


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="starts listening for newly registered certificates and sends slack alerts when it matches")
    parser.add_argument("-c", "--config", required=False, default="blackcert.conf",
                        help="path to the configuration file of blackcert")
    parser.add_argument("-o", "--output", required=False, default="results.log",
                        help="path to a JSON log file of the matches")
    parser.add_argument("-v", "--version", default=False, action="store_true", required=False,
                        help="shows current blackcert version")

    # parse them
    args = parser.parse_args()
    ARG_VERSION = args.version
    config = args.config
    OUTPUT_PATH = args.output

    print("""
_     _            _                 _   
| |   | |          | |               | |  
| |__ | | __ _  ___| | _____ ___ _ __| |_ 
| '_ \| |/ _` |/ __| |/ / __/ _ \ '__| __|
| |_) | | (_| | (__|   < (_|  __/ |  | |_ 
|_.__/|_|\__,_|\___|_|\_\___\___|_|   \__|                           
    """)

    # parse config
    blackcert_config = Path(config)
    if blackcert_config.is_file():
        print("blackcert {1} is using config at path {0}".format(blackcert_config, str(VERSION)))
        configpath = str(blackcert_config)
    else:
        print("ERROR: blackcert failed to find a config file at {0} or {1}..exiting".format(blackcert_config))
        sys.exit(1)

    # Parse config
    config = parse_configs(configpath)
    log = setup_logging(config['log_path'], 'INFO')

    if ARG_VERSION:
        log.info("version: {0}".format(VERSION))
        sys.exit(0)
    log.info("alerting to keywords: {0}".format(config['keywords']))

    #load suspicious words:
    suspicious_yaml = os.path.dirname(os.path.realpath(__file__)) + '/suspicious.yaml'
    with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)
    # certstream.listen_for_events(callback, on_open=on_open, on_error=on_error, url=config['certstream_url'])
    certstream.listen_for_events(callback, url=config['certstream_url'])
