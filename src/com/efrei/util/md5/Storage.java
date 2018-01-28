package com.efrei.util.md5;

import java.util.HashMap;
import java.util.Map;

public class Storage {
	private Map<Integer,String> map = new HashMap<Integer, String>();

	public Map<Integer, String> getMap() {
		return map;
	}
	public void setMap(int id, String cipher) {
		this.map.put(id, cipher);
	}
}
