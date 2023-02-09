# -*- coding: utf-8 -*-
"""
Criminalip.client
~~~~~~~~~~~~~

This module implements the Criminalip API. 
"""
import time 
import requests
import json 
from exception import APIError  

# Try to disable the SSL warnings in urllib3 since not everybody can install
# C extensions. If you're able to install C extensions you can try to run:
#
# pip install requests[security]
#
# Which will download libraries that offer more full-featured SSL classes
# pylint: disable=E1101
try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# Define a basestring type if necessary for Python3 compatibility
try:
    basestring
except NameError:
    basestring = str 


class Criminalip:
 
    def __init__(self, service, cip_key=None):
        """Initializes the API object. 
        """
        self.api_key = cip_key 
        self.base_url='https://api.criminalip.io'
        self._session = requests.Session()
        self.api_rate_limit = 1  # Requests per second
        self._api_query_time = None
        self._session.proxies = None  

    def _request(self, function, params, method='get'):
        """General-purpose function to create web requests to Criminalip.

        Arguments:
            function  -- name of the function you want to execute
            params    -- dictionary of parameters for the function

        Returns
            A dictionary containing the function's results.

        """ 
        base_url = self.base_url 
        headers = {"x-api-key": self.api_key}  

        # Wait for API rate limit
        if self._api_query_time is not None and self.api_rate_limit > 0:
            while (1.0 / self.api_rate_limit) + self._api_query_time >= time.time():
                time.sleep(0.1 / self.api_rate_limit)

        # Send the request
        try: 
            method = method.lower()
            if method == 'post':
                data = self._session.post(base_url + function, params)
            elif method == 'put':
                data = self._session.put(base_url + function, params=params)
            elif method == 'delete':
                data = self._session.delete(base_url + function, params=params)
            else: 
                data = self._session.get(base_url + function, params=params, headers=headers)   
            self._api_query_time = time.time()
        except Exception as exception : 
            raise APIError('Unable to connect to Climinal IP') 

        # Check that the API key wasn't rejected
        if data.status_code == 401:
            try:
                # Return the actual error message if the API returned valid JSON
                error = data.json()['error']
            except Exception as e:
                # If the response looks like HTML then it's probably the 401 page that nginx returns
                # for 401 responses by default
                if data.text.startswith('<'):
                    error = 'Invalid API key'
                else:
                    # Otherwise lets raise the error message
                    error = u'{}'.format(e)

            raise APIError(error)
        elif data.status_code == 403:
            raise APIError('Access denied (403 Forbidden)')
        elif data.status_code == 502:
            raise APIError('Bad Gateway (502)')

        # Parse the text into JSON
        try:
            #data = data.json()
            data = json.loads(data.text)
        except ValueError:
            raise APIError('Unable to parse JSON response')

        # Raise an exception if an error occurred
        if type(data) == dict and 'error' in data:
            raise APIError(data['error'])

        # Return the data
        return data
 
    def host(self, ip): 
        """Get all available information on an IP."""

        if isinstance(ip, basestring): 
            params = {} 
            params['ip'] = ip
            params['full'] = 'true'  
        return self._request('/v1/ip/data', params)

    def search_query(self, query, offset=0): 
        """Search the criminalip database.

        This method returns an iterator that can directly be in a loop. Use it when you want to loop over
        all of the results of a search query.

        :param query: Search query; identical syntax to the website
        :type query: str 

        :returns: A search query  that can be used as an iterator/ generator.
        """  
        if isinstance(query, basestring): 
            params = {} 
            params['query'] = query
            params['offset'] = offset
        return self._request('/v1/banner/search', params) 