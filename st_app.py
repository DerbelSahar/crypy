import streamlit as st
from crypy import main, container
import crypy
from crypy.services import StreamlitService
from dependency_injector import containers, providers
import sys


container.wire(modules=[sys.modules[__name__]], packages=[crypy])
with container.service.override(providers.Factory(StreamlitService)):
    main()

