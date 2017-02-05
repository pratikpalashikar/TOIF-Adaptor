package com.kdmanalytics.toif.pmd;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Stack;

import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import com.kdmanalytics.toif.framework.files.IFileResolver;
import com.kdmanalytics.toif.framework.utils.FindingCreator;
import com.kdmanalytics.toif.framework.xmlElements.entities.CodeLocation;
import com.kdmanalytics.toif.framework.xmlElements.entities.Element;
import com.kdmanalytics.toif.framework.xmlElements.entities.File;

public class PmdBugsParser extends DefaultHandler {

	private FindingCreator findingCreator;
	  
	  private String id;
	  
	  private Integer line;
	  
	  private Integer offset;
	  
	  private File file;
	  
	  private Properties props;
	  
	  private boolean first;
	  
	  private String description;
	  
	  private ArrayList<Element> traces = new ArrayList<>();
	  
	  private Stack<String> stack = new Stack<>();
	  
	  /**
	   * Used to resolve absolute file paths from relative paths
	   */
	  private IFileResolver resolver;

	String fileName;
	
	String ruleName;
	
	String beginLine;
	
	String endline;
	
	  
	  /**
	   * Table of files so we don't create duplicates
	   */
	  private Map<String, File> files = new HashMap<String, File>();
	  
	  /**
	   * construct a findbugs parser.
	   */
	  public PmdBugsParser(Properties props, IFileResolver resolver, String name, boolean unknownCWE) {
	    findingCreator = new FindingCreator(props, name, unknownCWE);
	    this.resolver = resolver;
	    this.props = props;
	  }
	  
	  /**
	   * start the parse. The details are handed to the findingCreator.
	   */
	  public void startElement(String uri, String localName, String qName, Attributes attrs) {
		  
		System.out.println("In start Element qName "+qName);
	    
	    if ("pmd".equals(qName)) {
			id = attrs.getValue("version");
			// first = true;
			traces.clear();
			// Reset the file to ensure we get a clean one each time
			file = null;
		}

		if ("file".equals(qName)) {

			fileName = attrs.getValue("name");
			// stack.push(qName);
			// first = true;
			System.out.println(fileName);
		}

		if ("violation".equals(qName)) {

			beginLine = attrs.getValue("beginline");
			System.out.println(beginLine);
			endline = attrs.getValue("endline");
			System.out.println(endline);
			ruleName = attrs.getValue("rule");
			System.out.println(ruleName);
			description = props.getProperty(ruleName);
			System.err.println(description);
			traces.add(new CodeLocation(Integer.parseInt(beginLine), null, Integer.parseInt(endline)));
			if (fileName != null) {

				if (files.containsKey(fileName)) {
					file = files.get(fileName);
				} else {
					file = new File(fileName);
					files.put(fileName, file);
				}

			}

		}
	   
	  }
	  
	  /**
	   * called on the end element.
	   */
	  public void endElement(String uri, String localName, String qName) {
		  
		  System.out.println("qName in end Element"+qName);
	   		
	   	  if ("violation".equals(qName)) {
			if (file == null) {
				if ("true".equals(System.getProperty("__DEBUG_IGNORE_MISSING_FINDBUGS_FILE"))) {
					findingCreator.create(description,ruleName, Integer.parseInt(beginLine), Integer.parseInt(endline), null, null, null, null,
							traces.toArray(new CodeLocation[traces.size()]));
				} else {
					System.err.println("Cannot find file for: [" + id + "] " + description);
				}
			} else {
				File afile = resolver.resolve(file);
				findingCreator.create(description,ruleName, Integer.parseInt(beginLine), Integer.parseInt(endline), null, file, null, null,
						traces.toArray(new CodeLocation[traces.size()]));
			}
		}	 
	   
	  }
	  
	  /**
	   * reuturn the gathered elements.
	   * 
	   * @return
	   */
	  public ArrayList<Element> getElements() {
	    return findingCreator.getElements();
	  }
	
	
}
