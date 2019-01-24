#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import re
import sys
import time
import random
import atexit
import logging
import argparse
import tempfile
import subprocess

import twisted
from lxml import etree

from Peach.Engine.engine import *
from Peach.Engine.common import *
from Peach.analyzer import Analyzer
from Peach.Analyzers import *
from Peach.agent import Agent

p = os.path.dirname(os.path.abspath(sys.executable))
sys.path.append(p)
sys.path.append(os.path.normpath(os.path.join(p, "..")))
sys.path.append(".")

peach_pids = []

@atexit.register
def cleanup():
    try:
        Engine.context.watcher.watchers[-1].OnCrashOrBreak()
    except:
        pass
    for pidfile in peach_pids:
        try:
            os.remove(pidfile)
        except OSError:
            pass


def save_peach_pid(agent=False):
    pid = os.getpid()
    filename = os.path.join(tempfile.gettempdir(), 'peach.%s%d' % ('' if not agent else 'agent.', pid))
    with open(filename, 'w') as fd:
        fd.write(str(pid))
    peach_pids.append(filename)


def fatal(msg):
    logging.error(highlight.error(msg))
    sys.exit(-1)

'''
The options essentially determine the behaviour of the fuzzer. So this is a good place to start and see what the 
fuzzer is doing. 
TODO Document each option in detail. That is pretty much what the app can do from a high level. 

'''
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Peach Runtime')
    parser.add_argument('-pit', metavar='path', help='pit file')  # TODO What is the difference between a pit and target
    parser.add_argument('-run', metavar='name', help='run name')
    parser.add_argument('-analyzer', nargs="+", help='load analyzer.') # TODO - What is this
    parser.add_argument('-parser', help='use specific parser.')
    parser.add_argument('-target', help='select a target pit.') # TODO Why the different pit and target.
    parser.add_argument('-macros', nargs='+', default=tuple(), help='override configuration macros') # TODO What is a Macro
    parser.add_argument('-seed', metavar='#', default=time.time(), help='seed') # TODO Why the seed.
    parser.add_argument('-debug', action='store_true', help='turn on debugging. (default: %(default)s)') # TODO What does store_true do here ?
    parser.add_argument('-new', action='store_true', help='use new relations.')  # TODO What is new?
    # Run just a single test case.
    parser.add_argument('-1', dest='single', action='store_true', help='run single test case.')
    # TODO How do we run a range of test cases.
    parser.add_argument('-range', nargs=2, type=int, metavar='#', help='run range of test cases.')
    # Validate the pit file. This might be a good place to start since this might give a sense of the pit file.
    parser.add_argument('-test', action='store_true', help='validate pit file.')
    # TODO I guess this just counts the number of tests cases run. Is this behaviour not default?
    parser.add_argument('-count', action='store_true', help='count test cases for deterministic strategies.')
    # TODO How do I specify this? What is test case number? Is it a uuid or what.
    parser.add_argument('-skipto', metavar='#', type=int, help='skip to a test case number.')
    # TODO Does the code not run in parallel already?
    parser.add_argument('-parallel', nargs=2, metavar=('#', '#'), help='use parallelism.')
    # TODO Why specify a way to start the agent? Aren't we already running the agent.
    parser.add_argument('-agent', nargs=2, metavar=('#', '#'), help='start agent.')
    # TODO This seems obvious, but how is this done. How id the logging done.
    parser.add_argument('-logging', metavar='#', default=20, type=int, choices=range(10, 60, 10),
                        help='verbosity level of logging')
    # TODO Check what ???
    parser.add_argument('-check', nargs=2, metavar=('model', 'samples'),
                        help='validate a data model against a set of samples.')
    # TODO Verbosity for what - the logging. This might be for the console.
    parser.add_argument('-verbose', action='store_true',
                        help='turn verbosity on. (default: %(default)s)') # Use -vvv action=count
    # Obvious, remove pyc files.
    parser.add_argument('-clean', action='store_true', help='remove python object files.')
    # Obvious get the version of the fuzzer.
    parser.add_argument('-version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    # Set up the logger. 
    logging.basicConfig(format='[Peach.%(name)s] %(message)s', level=args.logging)

    if args.pit and not args.pit.startswith('file:'):
        args.pit = 'file:' + args.pit  # Check if the passed pit file is a file.
    if args.target and not args.target.startswith('file:'):
        args.target = 'file:' + args.target  # Check that the passed target is a file as well.

    args.configs = {}  # args configs contains macros, target pit, and other options.
    for mac in args.macros:  # whats the difference between a macro and a program?
        k, v = mac.split('=', 1)
        args.configs[k.strip()] = v.strip()
    args.configs['_target'] = args.pit
    args.pit = args.target

    args.watcher = None
    args.restartFile = None
    peachrun = Engine()
    peachrun.configs = args.configs  # Transfer the configs to the Engine() just created.
    peachrun.SEED = args.seed
    random.seed(peachrun.SEED)  # Use the seed passed by the user to generate the test files.

    if args.debug:
        Engine.debug = True  # Set debug.

    if args.clean:      # Why do we need to delete these. I am guessing this is used if we make changes to the fuzzer
        #  and do not wish to have the old pyc files run, but rather force the interpreter to recompile.
        if sys.platform == "darwin" or sys.platform == "linux2":
            subprocess.call(["find", ".", "-name", ".DS_Store", "-delete"])
            subprocess.call(["find", ".", "-name", "*.pyc", "-delete"])
        elif sys.platform == "win32":
            subprocess.call(["del", "/S", "*.pyc"])
        sys.exit(0)

    if args.analyzer:
        try:
            cls = eval("%s()" % args.analyzer[0])  # Initialize the analyzer specified and assign it to cls.
            # by the user.
        except Exception as e:
            fatal("Loading analyzer failed: {}".format(e))
        if hasattr(cls, "supportCommandLine"):  # Check if the analyzer can be run on the command line.
            logging.info("Using %s as analyzer class." % args.analyzer[0])
            a = {}
            for pair in args.analyzer[1:]:
                key, val = pair.split("=")
                a[key] = val
            try:
                cls.asCommandLine(a)    # Seems like this is being run in the command line now. But how? Note that is
                #  using the dictionary to run the analyzer using the asCommandLine. This implies that each analyzer
                # that has the ability to run via the command line must also have a function to run the same.

            except Exception as e:
                fatal(e)
        else:
            fatal("Analyzer does not support command line usage.")
        sys.exit(0)

    if args.parser:
        try:
            cls = eval(args.parser) # cls is reassigned this implies that the analyzer os run and let loose. We don't
            # seem to keep a reference to it. This is similar to the Analyzer the way it is set up we also set this
            # if provided perhaps by the user.
            # The only difference here is that the Parser is not evaluated in the same way as the Analyzer, i.e it is
            # missing. The reason I think is that we can here support python inbuilt or installed parsers. Note line
            # 70 in parser.py. It uses the parser etree.XMLParser(remove_comments=True.
        except Exception as e:
            fatal("Loading parser class failed: {}".format(e))
        if hasattr(cls, "supportParser"):
            logging.info("Using {} as parser.".format(args.parser))
            args.parser = cls()     # If the parser is supported then use it. This is a bit confusing, since we set
            # the parser using eval. EXPLAINED on line 161 above.
        else:
            fatal("Analyzer does not support parser usage.")
    else:
        args.parser = PitXmlAnalyzer()  # If the parser is set here does that mean that all this is to parse the pit
        # file and not the target file format. That does seem like the most likely case.
    args.parser.configs = args.configs  # Seems to be parsing all the config elemnets to the parser configs. 

    if args.new:
        Engine.relationsNew = True

    if args.check and args.pit:
        from Peach.Engine.incoming import DataCracker
        dataModelName = args.check[0]
        samplesPath = args.check[1]
        samples = []
        if os.path.isdir(samplesPath):
            for fp in os.listdir(samplesPath):
                samples.append(os.path.join(samplesPath, fp))
        else:
            samples = glob.glob(samplesPath)
        peach = args.parser.asParser(args.pit)
        dataModel = peach.templates[dataModelName]
        for sample in samples:
            dataModel = peach.templates[dataModelName].copy(peach)
            with open(sample, "rb") as fd:
                data = fd.read()
            buff = PublisherBuffer(None, data, True)
            cracker = DataCracker(peach)
            cracker.optmizeModelForCracking(dataModel, True)
            cracker.crackData(dataModel, buff)
            if dataModel.getValue() == data:
                result = highlight.ok("passed")
            else:
                result = highlight.error("failed")
            logging.info("[%s] cracking: '%s'" % (result, sample))
        logging.info("Done.")
        sys.exit(0)

    if args.single:
        logging.info("Performing a single iteration.")
        Engine.justOne = True

    if args.range:
        if args.range[0] < 0:
            fatal("Count for start must be positive.")
        if args.range[0] >= args.range[1]:
            fatal("Range must be 1 or larger.")
        logging.info("Performing tests from {} -> {}".format(args.range[0], args.range[1]))
        Engine.testRange = args.range

    if args.parallel:
        if args.parallel[0] < 1:
            fatal("Machine count must be >= 2.")
        if args.parallel[0] <= args.parallel[1]:
            fatal("The total number of machines must be less than current machine.")
        logging.debug("Parallel total machines: {}".format(args.parallel[0]))
        logging.debug("Parallel our machine   : {}".format(args.parallel[1]))

    if not args.pit and not args.agent:
        logging.error("You must provide a pit or an agent.")
        sys.exit(-1)

    if args.test:
        try:
            args.parser.asParser(args.pit)
            logging.debug(highlight.ok("File parsed without errors."))
        except PeachException as e:
            logging.exception(e.msg)
        except etree.LxmlError as e:
            logging.exception("An error occurred while parsing the XML file: {}".format(e))
        except:
            raise
        sys.exit(0)

    if args.count:
        try:
            peachrun.Count(args.parser.asParser(args.pit), args.run)
        except PeachException as e:
            logging.error("Counting test cases only works with deterministic strategies.")
            fatal(e)
        sys.exit(0)

    if args.agent:
        save_peach_pid(agent=True)
        try:
            port = int(args.agent[0])
        except ValueError as e:
            fatal("Agent port is not a valid number.")
        password = args.agent[1]
        try:
            logging.info("Attempting to start Agent ...")
            agent = Agent(password, port)
        except twisted.internet.error.CannotListenError as e:
            fatal(e)
        sys.exit(0)
    else:
        save_peach_pid(agent=False)

    logging.info("Using random seed: %s" % peachrun.SEED)
    try:
        peachrun.Run(args)
    except PeachException as e:
        logging.exception(e.msg)
    except etree.LxmlError as e:
        logging.exception("An error occurred while parsing the XML file: {}".format(e))
    except:
        raise
    finally:
        if DomBackgroundCopier.copyThread is not None:
            DomBackgroundCopier.stop.set()
            DomBackgroundCopier.needcopies.set()
            DomBackgroundCopier.copyThread.join()
            DomBackgroundCopier.copyThread = None
