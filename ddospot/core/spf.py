#!/usr/bin/env python3

import ast
import os
import sys
import imp

from . import utils

# slightly modified version of SPF (Simple Plugin Framework) by Regis Decamps
# https://github.com/regisd/simple_plugin_framework

PLUGIN_DIRECTORY = "pots"


class MountPoint(type):
    """
    * A way to declare a mount point for plugins. Since plugins are an example of loose coupling, there needs to be a neutral location, somewhere between the plugins and the code that uses them, that each side of the system can look at, without having to know the details of the other side.
    * A way to register a plugin at a particular mount point. Since internal code don't want to look around to find plugins that might work for it, there needs to be a way for plugins to announce their presence. This allows the guts of the system to be blissfully ignorant of where the plugins come from; again, it only needs to care about the mount point.
    * A way to retrieve the plugins that have been registered. Once the plugins have done their thing at the mount point, the rest of the system needs to be able to iterate over the installed plugins and use them according to its need.

    Add the parameter `metaclass = MountPoint` in any class to make it a mount point.

    """

    def __init__(cls, name, bases, attrs):
        if not hasattr(cls, 'plugins'):
            # This branch only executes when processing the mount point itself.
            # So, since this is a new plugink type, not an implementation, this
            # class shouldn't be registered as a plugink. Instead, it sets up a
            # list where plugins can be registered later.
            cls.plugins = []
        else:
            # This must be a plugink implementation, which should be registered.
            # Simply appending it to the list is all that's needed to keep
            # track of it later.
            cls.plugins.append(cls)


class ExtensionsAt(object):
    """ Descriptor to get plugins on a given mount point.
    """

    def __init__(self, mount_point):
        """ Initialize the descriptor with the mount point wanted.
        """
        self.mount = mount_point

    def __get__(self, instance, owner=None):
        """ Returns all plugins on this mount point.
        """
        return [p() for p in self.mount.plugins]


def list_plugins():
    """
    Utility method to list available plugins
    """
    l = list()
    for dir in os.listdir(PLUGIN_DIRECTORY):
        l.append(dir)
    return l


def load_plugins(**kwargs):
    """
    Utility method to load plugins.
    If neither `name` nor `names` are specified, it loads all modules found in PLUGIN_DIRECTORY.
    @type  ignored: a list of string
    @param ignored: the list of plugins to ignore (by name)
    @type name: a string
    @param name: name of a single plugin to load
    @type names: a list of string
    @param names: the list of plugins to load. If undefined, plugins from PLUGIN_DIRECTORY are loaded
    @return The list of loaded modules
    """
    ignored_plugins = ()
    names = None
    for key in kwargs:
        if key == 'ignore':
            ignored_plugins = kwargs[key]
        elif key == 'names':
            names = kwargs[key]
        elif key == 'name':
            names = (kwargs[key],)
    if names is None:
        names = list_plugins()
    loaded_plugins = {}
    for addon in names:
        if addon in ignored_plugins:
            utils.print_warn('Plugin %s not loaded because it is disabled' % (addon))
            continue
        if addon in loaded_plugins:
            utils.print_warn('Plugin %s not reloaded because it has already been loaded' % (addon))
            continue
        try:
            file = None
            file, path, description = imp.find_module(addon, [PLUGIN_DIRECTORY])
            module = imp.load_module(addon, file, path, description)
            loaded_plugins[addon] = module
        except:
            # not a big deal, but file may have been opened by find_module
            if file is not None:
                file.close()
                # and printing the stack can help understand what happened
            utils.print_warn('Plugin %s not loaded properly - %s' % (addon, sys.exc_info()[1]))

    return loaded_plugins


def get_module_info(name):
    filename = os.path.join(PLUGIN_DIRECTORY, name, '__init__.py')
    info = {}
    with open(filename) as f:
        tree = ast.parse(f.read(), filename=filename)
        for item in tree.body:
            if isinstance(item, ast.Assign):
                attr = item.targets[0].id
                if attr in ('__author__', '__version__', '__desc__'):
                    info[attr] = item.value.s
        return info
