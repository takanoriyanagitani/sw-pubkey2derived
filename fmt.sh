#!/bin/sh

xcrun swift-format \
	format \
	--in-place \
	--recursive \
	--ignore-unparsable-files \
	--parallel \
	--color-diagnostics \
	./Sources \
  ./Tests \
	./Package.swift
