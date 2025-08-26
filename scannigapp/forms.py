from django import forms

class UserForm(forms.Form):
    url=forms.URLField(label="Enter Your Url for Scanning...")
    crawl=forms.BooleanField(required=False,initial=True,label="Enable for crawlling")
    max_pages=forms.IntegerField(initial=2,required=True,min_value=1,max_value=50,label="Enter the number of pages to crawl")
    confirm=forms.BooleanField(label="I confirm I own or have permission to test this target")
    