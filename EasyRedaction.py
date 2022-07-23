import os
import re
import fitz
import pdfrw
from pdfrw import PdfReader

#Returns a generator of sensitive data from passed lines
#lines can be read from pdf
def getSensitiveData(lines):
    emailExceptions = ["@lacity.org"]

    #Email regex
    EMAIL_REG = r"([\w\.\d]+\@[\w\d]+\.[\w\d]+)"
    for line in lines:
        if re.search(EMAIL_REG, line, re.IGNORECASE):
            search = re.search(EMAIL_REG, line, re.IGNORECASE)
            #Convert re.Match object to a string
            searchStr = search.string
            l = len(searchStr)
            domain = searchStr[searchStr.index('@'):l]
            if domain not in emailExceptions:
                print("Redacting ... {}".format(searchStr))

                #yields creates a generator
                #generator is used to return
                #values in between function iterations
                yield search.group(1)
            else:
                print("{} is an exception".format(searchStr))


#********************   REDACTION   ********************

# Obtain names of each file in current directory
entries = os.scandir()

# Loop through each file
for entry in entries:
    # String length used for substring
    l = len(entry.name)
    fileType = (entry.name[l - 4:l]).lower()
    if (fileType == ".pdf"):
        #Save name without extension
        fileName = entry.name[0:l - 4]

        # Create fitz (PyMuPDF) object
        record = fitz.open(entry.name)
        print("Checking file {}".format(entry.name))

        #Reset overwrite for current pdf
        #If no redactions applied, do not overwrite
        overwrite = False

        #Loop through each page in the current pdf
        for page in record:

            # _wrapContents is needed for fixing
            # alignment issues with rect boxes in some
            # cases where there is alignment issue
            #page._wrapContents()

            #Get rect boxes which consists the matching email regex
            sensitive = getSensitiveData(page.get_text("text").split('\n'))

            if sensitive:
                for data in sensitive:
                    overwrite = True
                    areas = page.search_for(data)

                    #Draw outline over sensitive datas
                    [page.add_redact_annot(area, fill=(0, 0, 0)) for area in areas]

            #Apply redaction
            page.apply_redactions()

        #Overwrite redacted pdf
        if overwrite:
            record.save("{}_redacted.pdf".format(fileName))
            print("Successfully redacted\n")

#End of program
input("Press Enter to continue...")