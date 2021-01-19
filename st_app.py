import streamlit as st
from crypy import main, container
import crypy
from crypy.services import StreamlitService
from dependency_injector import containers, providers
from streamlit.errors import DuplicateWidgetID
import sys

def local_css(filename):
    with open(filename) as f:
        st.markdown('<style>{}</style>'.format(f.read()), unsafe_allow_html=True)

container.wire(modules=[sys.modules[__name__]], packages=[crypy])
with container.service.override(providers.Factory(StreamlitService)):
    
    try:
        #local_css("assets/style.css")
        main()
    except DuplicateWidgetID as e:
        print(e)

