#!/usr/bin/python

import pickle
import gib_detect_train

class GibDetector(object):

	def __init__(self):
		model_data = pickle.load(open('lib/gib_model.pki', 'rb'))
		self.model_mat = model_data['mat']
		self.threshold = model_data['thresh']		
		
	def getRating(self, string):
		return gib_detect_train.avg_transition_prob(string, self.model_mat) > self.threshold

	def getScore(self, string):
		return round(gib_detect_train.avg_transition_prob(string, self.model_mat) / self.threshold, 2)
