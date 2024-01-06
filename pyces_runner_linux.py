"""
-------------------------------
*******************************
Nitin Ramesh
Mail: nitin.n.ramesh@gmail.com
Web: www.nitinramesh.com
*******************************
-------------------------------
"""
import subprocess
import sys
import os
import datetime
import shutil
import logging
import time
import zipfile

def main(): 
 #################################################################################################
 #Initialization and SP Command execution functions
 
 def command_execution(args):
  sub_ret = subprocess.Popen(args,stdout=subprocess.PIPE,shell=True)
  return_code = sub_ret.stdout.read()
  return return_code
 
 def command_execution_2(args,working_directory):
  sub_ret = subprocess.Popen(args,stdout=subprocess.PIPE,shell=True,cwd=working_directory)
  return_code = sub_ret.stdout.read()
  return return_code 
 
 #################################################################################################
 #Defined the base_path and src_path
 
 def get_base_path():
  base_path = os.path.dirname(os.path.abspath(__file__))
  base_path = base_path.rstrip() 
  base_path = str(base_path)
  return base_path
 
 def get_src_path():
  base_path = get_base_path()
  src_path = base_path + "/Test_Project"
  return src_path
  
 def get_res_path():
  base_path = get_base_path()
  res_path = base_path + "/Results"
  return res_path
 
 #################################################################################################
 #Cleanup function for post scan success or exception handling:
  
 def clear_path():
  try:
   clr_path = get_src_path()
   
   for root, dirs, files in os.walk(clr_path):
       for f in files:
           os.unlink(os.path.join(root, f))
       for d in dirs:
           shutil.rmtree(os.path.join(root, d))
  except:
   logging.error("Path is not cleared,Code Red! Code Red!")   
 
 #################################################################################################
 #Cleanup function for folders on scan run:
 
 def folder_clean():
  base_path = get_base_path()
  for file in os.listdir(base_path):
    if(file.endswith(".xml") or file.endswith(".html")):
     os.remove(file)

 ################################################################################################ 
 #Parsing the scan type to run:

 HelpText = """
 Welcome to the PyCes Runner!
 Syntax to run : python pyces_runner.py option[Type of severity to run]
 
 Please select the severity you wish to run:
 1 : Normal [Recommended]
 2 : High [May lead to high number of false positives]
 
 Example:
 python pyces_runner.py 1
 """
 
 print ("***********************************************************")
 print ("------------------PYCES SCANNER LAUNCHED------------------")
 print ("***********************************************************")

 #print ("RGV2ZWxvcGVkIGJ5IE5pdGluIFJhbWVzaCwgVmVkIFByYWJodSBhbmQgQW51YmhhdiBTaGFybWE=")

 #ruleset = input("Enter the sensitivity level of the scan 1:Normal 2:High or -h for help \n")
 if(sys.argv[1] == '1'):
  rule_type = "Normal"
 elif(sys.argv[1] == '2'):
  rule_type = "High"
 elif(sys.argv[1] == '-h' or sys.argv[1] == '-help'):
  print(HelpText) 
  sys.exit(0)
 else:
  #print ("\nThe option entered by you is invalid,Please use -h for help section.\n")
  #sys.exit(0)  
  rule_type = "Normal"
 
 #################################################################################################
 #Setting the date & time of the report & total time taken:
 
 start_time = time.time()
 
 now = datetime.datetime.now()
 day = str(now.day)
 month = str(now.month)
 year = str(now.year)
 hour = str(now.hour)
 minute = str(now.minute)
 second = str(now.second)
 html_date = day + "/" + month + "/" + year + "  " + hour + ":" + minute + ":" + second 
 
 #################################################################################################
 #Setting up the logging mechanism
 
 base_path = get_base_path()
 log_file = base_path + "/Repository/logs/log_file.log"
 
 logging.basicConfig(filename=log_file, filemode='a+', level=logging.DEBUG)
 
 logging.info("#######################################################")
 logging.info("PyCes Initialized : " + html_date)
 
 loglist = list()
 
 src_path = get_src_path()
 lflag = 0
 for root, dirs, files in os.walk(src_path):
  if not (lflag == 3):
   loglist.append(root)
  else:
   break     
  lflag += 1  
 print("Yo\n")
 print(loglist)
#  logging.info("Detecting libraries at path:" +loglist[1])
 logging.info("Detecting libraries at path:" +loglist[0])
 
 ################################################################################################
 #Clear the Previous files 
 
 folder_clean()
 
 ################################################################################################ 
 #Setting the commands to run from here:
 
 base_path = get_base_path()
 try:
  if(len(sys.argv) > 3):
   print ("\nPlease provide only one argument or use -h for help\n")
   sys.exit(0)
   """  
   elif(len(sys.argv) < 2):
   File_type = "html"
   rule_type = sys.argv[1]"""
  else:
   File_type = "html"	
   rule_type = rule_type
 except Exception:
  print ("\nError : Please try again or use -h for help\n")
 try: 
  if(File_type.lower() == "html"):
   Output_file = open("Pyces_Report.html","w")
   src_path = get_src_path()
   args1 = 'cloc '+ src_path +' --out=cloc.txt'
   src_path = get_src_path()
   args2 = 'bandit -r '+ src_path + '/' +' -f html -o bandit_result.html'
   base_path = get_base_path()
   dep_path = base_path + "/Repository/dependency-check/bin"
   src_path = get_src_path()
   base_path = get_base_path()
   args3 = './dependency-check.sh -s '+ src_path + '/' +' --project trial_project -o '+ base_path 
   base_path = get_base_path()
   pymcd_path = base_path + "/Repository/Grep_Tool/python/"
   src_path = get_src_path()
   base_path = get_base_path()
   #CRR paths set at this point
   args4 = 'python pymcd.py ' + src_path +' ' +base_path+ ' '+rule_type
   dir_2 = pymcd_path
  else:	
   print ("\nPlease provide the right format or use -h for help\n")
   sys.exit(0)
 except Exception:
  logging.error("Warning!,Unrecognized error, Aborting Automated Scan!")
  sys.exit("\nSorry something is wrong please try again with the specific option or use '-h' for help\n")  
 #############################################################################################################################################
 #Detecting third party libraries here
 
 def libdetector(path):
  thirdpartyfile = base_path + "/Repository/Thirdpartylibs.txt" 
  
  count3 = 0
  flag = 0
  paths = list()
  exists = list()
 
  exists.append("start") 
 
  for root, dirs, files in os.walk(path):
   paths.append(root)
 
  with open(thirdpartyfile) as tpf:
   tpl = tpf.readlines() 
 
  ref1 = """ \n
  The following Third Party libraries were detected:
  -----------------------------------------------------  \n"""
 
  for i in range(0,len(tpl)):
   for j in range(0,len(paths)):
    tpl[i] = tpl[i].rstrip()
    if  tpl[i].lower() in paths[j].lower():
     for k in range(0,len(exists)):
      flag = 0
      if tpl[i] in exists[k]:
       flag = 1
       k = 0
       break
      k = k + 1
     if flag == 0:
      exists.append(tpl[i])
      ref1 += "\n" + tpl[i].rstrip() + " library detected " +"at "+ paths[j] +"\n"
      ref1 += "*" *20
     else:	
      continue
    #count2 = count2 + 1
   #count1 = count1 + 1
   #count2 = 0
  if exists.count("start") == len(exists):
   ref1 += "\n"+" No Third Party Libraries are present in the folder. " +"\n"
 
  ref3 ="""
  -----------------
  Reference Library
  -----------------
 
  No	Name of Component	Version number of component 
  1	    boto - AWS for Python		2.26.0
  2 	Python httplib2			0.9
  3	    Python sortedcontainer		0.9.5
  4	    Bootstrap			2.3.2
  5	    jqBootstrapValidation		1.3.7
  6	    select2				3.5.2
  7	    RemotePDB			1.2
  8	    jquery-cookie			1.4.1
  9	    pxGrid_Search.jar		NA
  10	Bootstrap table			1.9.1
  11	BigSuds				1.0.1
  12	suds				0.4
  13	apache axis			1.1
  14	castor				1.3
  15	apache commons discovery	0.2
  16	apache commons logging		1.1.1
  17	gson				2.2.4
  18	hessian				3.0.8
  19	apache log4j			1.2
  20	mx4j				3
  21	opencsv				2.3
  22	wsdl4j				1.6
  23	xerces				2.x
  24	simplejson			3.6.2
  25	javax.management.j2ee		6
  26	jboss-cli-client		6.4
  27	slf4j				1.7.5
  28	fastjson			1.2.5
  29	apache commons configuration	1.1
  30	apache commons collections	3.2.1
  31	apache commons pool		2.3
  32	apache commons io		2.4
  33	guava				18
  34	Quartz.net			2.1.1
  35	Unity				3.0.1304, 2.1.505.2
  36	CommonServiceLocator		1
  37	Common.Logging			2.1.2
  38	Common.Logging.NLog20		2.1.2
  39	NLog				2.0.1.2
  40	SlowCheetah			2.5.11
  41	xUnit.net, xUnit.extensions	1.9.1
  42	SpecFlow, SpecFlow.xUnit	1.9.0
  43	defusedxml			0.4.1
  44	nfcapd & nfdump 		1.6.8
  45	Remote PDB			1.1.3
  46	futures				3.0.3
  """
  output = str(ref1) + str(ref3)
  return output
 #################################################################################################
 #Running th OS commands from this block:
 
 print ("Starting Automated Testing \n")
 print ("Running Cloc\n")
 command_execution(args1) # This output is not saved,it is read from file
 print ("Successful! \n")
 print ("Running Bandit Analyser\n")
 command_execution(args2) # This output is not saved,it is read from file
 print ("Successful!, Bandit Output file created in the result folder \n")
 print ("Checking for 3rd party libraries\n")
 src_path = get_src_path()
 output2 = libdetector(src_path)
 print ("Successful! \n")
 print ("Running Dependency Check \n")
 dir_1 = dep_path
#  print("This is the command: " + args3 + " and " + dir_1)
 command_execution_2(args3,dir_1)
 print ("Successful! \n")
#  print ("Running Grepper \n")
#  print("This is the command: " + args4 + " and " + dir_2)
#  command_execution_2(args4,dir_2)
#  print ("Successful! \n")
 print ("Writing Output to files...\n")
 
 #################################################################################################
 #Running th OS commands from this block: 
 
 def html_wite(date, rule_type, output1=None, output2=None, output3=None, output4=None, output5=None, output6=None, output7=None, output8=None, output9=None, output10=None):
 
  content="""<!DOCTYPE html>
  <html>
  <head>
  
  <title>
      Pyces Automated Testing Report
  </title>
  
  <style> 
 
  html * {
      font-family: "Arial", sans-serif;
  }
  
  pre {
      font-family: "Monaco", monospace;
      white-space: pre-wrap;       /* css-3 */
      white-space: -moz-pre-wrap !important;  /* Mozilla, since 1999 */
      white-space: -pre-wrap;      /* Opera 4-6 */
      white-space: -o-pre-wrap;    /* Opera 7 */
      word-wrap: break-word;       /* Internet Explorer 5.5+ */   
  }
  
  a:link    {color:black}
  a:visited {color:black}
  a:hover {color:red}
  
  h3,pre
  {
  padding : 0px;
  margin : 0px;
  } 
  
  .bordered-box {
      border: 1px solid black;
      padding-top:.5em;
      padding-bottom:.5em;
      padding-left:1em;
 
  }
  
  .metrics-box {
      font-size: 1.1em;
      line-height: 130%;
  }
  
  .metrics-title {
  <!--    font-size: 1.5em;-->
      font-weight: 500;
      margin-bottom: .25em;
  }
 
  .tabby-description {
      font-size: 1.3em;
      font-weight: 500;
  }
 
  .candidate-tabbys {
      margin-left: 2em;
      border-left: solid 1px; LightGray;
      padding-left: 5%;
      margin-top: .2em;
      margin-bottom: .2em;
  }
 
  .tabby-block {
      border: 1px solid LightGray;
      padding-left: .5em;
      padding-top: .5em;
      padding-bottom: .5em;
      margin-bottom: .5em;
      width: 98%;
  }
 
  .tabby-sev-high {
      background-color: SkyBlue;
  }
  
  .tabby-sev-medium {
    background-color: FloralWhite;
  }
  
  .tabby-sev-low {
      background-color: PapayaWhip;
  }


table {
  table-layout: fixed;
  width: 100%;
}

table td {
    word-wrap: break-word;
    overflow-wrap: break-word;
}

  </style>
  </head> 
 
  <body>
 
  <span id='metrics'>
      <div class='metrics-box bordered-box'>
          <div class='metrics-title'>
              <br><h1>Pyces Automated Test Report</h1>
          <h3>Test Run On : (23/10/2017  15:58:33 IST)</h3></br>
      </span>
     
  <span id='tabby-0'>
  <div class='tabby-block tabby-sev-high'>
  <h3>Contents:</h3>
  <pre></br>
  1) <a href="#tabby-1" style="text-decoration:none">Cloc Ouput</a>
  2) <a href="#tabby-2" style="text-decoration:none">Third party libraries</a>
  3) <a href="#tabby-3" style="text-decoration:none">Bandit Output</a>
  4) <a href="#tabby-4" style="text-decoration:none">Dependency check Report</a>
  5) <a href="#tabby-5" style="text-decoration:none">CR Runner Results</a>
  </pre>
  </div>
  </span>
  <span id='tabby-1'>
  <div class='tabby-block tabby-sev-medium'>
  <h3>Cloc Output:</h3>
  <pre>""" + output1 + """</pre>
  </div>
 </span>
  <span id='tabby-2'>
  <div class='tabby-block tabby-sev-low'>
  <h3>Third Party Libraries detected in Code:</h3>
  <pre>"""+ output2 + """</pre>
  </div>
  </span>
  <span id='tabby-3'>
  <div class='tabby-block tabby-sev-medium'>
  <h3>Bandit Findings:</h3>
  <pre>"""+ output3 + """</pre>
  </div>
  </span>
  <span id='tabby-4'>
  <div class='tabby-block tabby-sev-low'>
  <h3>Dependency Check Output:</h3>
  <pre>"""+ output4 + """</pre>
  </div>
  </span>
  <!-- This tool is brought to you by the collective effort of Nitin Ramesh, Anubhav Sharma and Ved Prabhu from Cigital Bangalore. -->
  <!--
  *******************************
  For any Questions or Feedback
  Contact:
  Nitin Ramesh
  Mail: nramesh@cigital.com / nitinram@synopsys.com
  +1 (703) 404-9293 x7024 
  ******************************* -->
  </body>
  </html>    """
 
  return content 
 #################################################################################################
 #Preparing html contents file here:
 print ("\nStarting Reporting Phase\n")
 try: 
  cloc_output_file = open("cloc.txt","r")
 
  output1 = cloc_output_file.read() #cloc output
 
  output2 = str(output2) #3rd party output
 
  file_contents_bandit = open("bandit_result.html","r")
  file_contents_dependency = open("dependency-check-report.html","r")
#   file_contents_grepper = open("Findings_Report.htm","r")
  output3 = file_contents_bandit.read() #bandit file contents
  output4 = file_contents_dependency.read() #dependency check contents
#   output4 = str(output4)
#   output5 = file_contents_grepper.read()
#   content = html_wite(html_date,rule_type,output1,output2,output3,output4,output5)
  output4 = str(output4)
#   output5 = file_contents_grepper.read()
  content = html_wite(html_date,rule_type,output1,output2,output3,output4)
  Output_file.write(content)
 
 #################################################################################################
 #Clean any open resources 
 
 finally:
  cloc_output_file.close()
  file_contents_bandit.close()
  file_contents_dependency.close()
#   file_contents_grepper.close() 
  Output_file.close()
 
 os.remove("cloc.txt")
 os.remove("bandit_result.html")
 os.remove("dependency-check-report.html")
#  os.remove("Findings_Report.htm")
 
 
 #################################################################################################
 #Copying result to Results folder archives
 
 res_tmp = get_res_path()
 result_path = str(res_tmp) + "/" + str(now.year) +"_"+ str(now.month) +"_"+ str(now.day) +"_"+ str(now.hour) +"_"+ str(now.minute) +"_"+ str(now.second) 
 
 if not os.path.exists(result_path):
     os.makedirs(result_path)
 
 file_src = "Pyces_Report.html"
 shutil.copy(file_src,result_path)

 #################################################################################################
 #Copying Results to XXXXX Network drive
 #Dont change - Deprecated
 def network_backup():
  try:
   #Add your path here to store on a network drive
   res2_tmp ="\\\\XXXXX\\Documents\\Nitin_Ramesh\\SATT_Results"
   result2_path = str(res2_tmp) + "\\" + str(now.year) +"_"+ str(now.month) +"_"+ str(now.day) +"_"+ str(now.hour) +"_"+ str(now.minute) +"_"+ str(now.second) +"\\"
   #print result2_path
   if not os.path.exists(result_path):
    os.makedirs(result2_path)
   shutil.copy2(file_src,result2_path)
  
  except Exception:
   logging.error("The network share is not currently accessible,Please Debug this issue.")      
 
 #################################################################################################
 #Cleaning Test_Project folder for next test

 
 #Activate Cleanup here for successful completion
 clear_path()
 
 #Activate network share here
 #network_backup()
 
 logging.info("Test_Project project folder has been cleared!")
 logging.info("System ready for next test")
 
 print ("Please collect your output file(s) from the Results folder\n")

 print ("***********************************************************")
 print ("-------------------------POD STARK------------------------")
 print ("***********************************************************")

 end_time = time.time()
 tot_time = end_time - start_time
 
 logging.info("Test Completed Successfully " + str(tot_time) +" seconds")
 #################################################################################################
#Call to main function here

main()

##################################################################################################
##End of program - PyCes Code                                                                   ##
##################################################################################################
