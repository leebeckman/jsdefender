/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * ShowConversationAction.java
 *
 * Created on August 24, 2004, 11:07 PM
 */

package org.owasp.webscarab.ui.swing;

import java.awt.Component;
import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.JOptionPane;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.FrameworkModel;

/**
 *
 * @author  knoppix
 */
public class TagConversationAction extends AbstractAction {
    
	/**
	 * 
	 */
	private static final long serialVersionUID = -55516030560746658L;
	private Component parent;
	private FrameworkModel _model;
	
    /** Creates a new instance of ShowConversationAction */
    public TagConversationAction(Component parent, FrameworkModel model) {
    	_model = model;
        putValue(NAME, "Tag conversation");
        putValue(SHORT_DESCRIPTION, "Assign a user-defined tag to this conversation");
        putValue("CONVERSATION", null);
    }
    
    public void actionPerformed(ActionEvent e) {
        Object o = getValue("CONVERSATION");
        if (o == null || ! (o instanceof ConversationID)) return;
        ConversationID id = (ConversationID) o;
        String tag = _model.getConversationProperty(id, "TAG");
        tag = JOptionPane.showInputDialog(parent, "Tag the conversation", tag == null ? "" : tag);
        _model.setConversationProperty(id, "TAG", tag);
    }
    
    public void putValue(String key, Object value) {
        super.putValue(key, value);
        if (key != null && key.equals("CONVERSATION")) {
            if (value != null && value instanceof ConversationID) {
                setEnabled(true);
            } else {
                setEnabled(false);
            }
        }
    }
    
}
