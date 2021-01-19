from crypy import main, container
import sys
import crypy

if __name__ == '__main__':
    container.wire(modules=[sys.modules[__name__]], packages=[crypy])
    main()