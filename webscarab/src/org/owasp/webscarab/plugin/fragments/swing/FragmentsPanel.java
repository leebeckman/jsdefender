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
 * FragmentsPanel.java
 *
 * Created on 09 December 2004, 10:37
 */

package org.owasp.webscarab.plugin.fragments.swing;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

import org.owasp.webscarab.plugin.fragments.Fragments;
import org.owasp.webscarab.plugin.fragments.FragmentsModel;
import org.owasp.webscarab.plugin.fragments.FragmentListener;

import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.ui.swing.ConversationTableModel;
import org.owasp.webscarab.ui.swing.ColumnWidthTracker;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.MultiLineCellRenderer;
import org.owasp.webscarab.util.swing.ListComboBoxModel;

import javax.swing.JPanel;
import javax.swing.Action;
import javax.swing.AbstractAction;
import javax.swing.DefaultListModel;
import javax.swing.SwingUtilities;
import javax.swing.ListSelectionModel;
import javax.swing.JList;

import java.awt.Component;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import java.util.Map;
import java.util.HashMap;
import javax.swing.AbstractListModel;

/**
 *
 * @author  rogan
 */
public class FragmentsPanel extends javax.swing.JPanel implements SwingPluginUI {
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 383270526566796972L;

	private FragmentsModel _model = null;
    
    private String _type = null;
    
    private Action[] _conversationActions;
    private Action[] _urlActions;
    private Map<String, ColumnDataModel> _conversationColumns = new HashMap<String, ColumnDataModel>();
    private Map<String, ColumnDataModel> _urlColumns = new HashMap<String, ColumnDataModel>();
    
    private DefaultListModel _typeListModel = new DefaultListModel();
    private FragmentListModel _flm = new FragmentListModel();
    
    private Listener _listener = new Listener();
    
    private static final ColumnDataModel[] CDM = new ColumnDataModel[0];
    
    /** Creates new form FragmentsPanel */
    public FragmentsPanel(Fragments fragments) {
        initComponents();
        _model = fragments.getModel();
        
        fragmentList.setCellRenderer(new FragmentRenderer());
        fragmentList.setModel(_flm);
        fragmentList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        _typeListModel.addElement(FragmentsModel.KEY_COMMENTS);
        _typeListModel.addElement(FragmentsModel.KEY_SCRIPTS);
        
        
        _typeListModel.addElement(FragmentsModel.KEY_HIDDENFIELD);
        _typeListModel.addElement(FragmentsModel.KEY_FILEUPLOAD);
        _typeListModel.addElement(FragmentsModel.KEY_DOMXSS);
        _typeListModel.addElement(FragmentsModel.KEY_FORMS);
        
        typeComboBox.setModel(new ListComboBoxModel(_typeListModel));
        typeComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                _type = (String) typeComboBox.getSelectedItem();
                _flm.setFilter(null, _type);
            }
        });
        
        fragmentList.addListSelectionListener(new FragmentsListListener());
        conversationTable.setModel(new ConversationTableModel(_model.getConversationModel()));
        ColumnWidthTracker.getTracker("ConversationTable").addTable(conversationTable);
        
        createActions();
        
        _model.addModelListener(_listener);
        
    }
    
    private void createActions() {
        _conversationActions = new Action[] {
            new FragmentsAction("CONVERSATION", FragmentsModel.KEY_SCRIPTS),
            new FragmentsAction("CONVERSATION",FragmentsModel.KEY_COMMENTS)
        };
        _urlActions = new Action[] {
            new FragmentsAction("URL", FragmentsModel.KEY_SCRIPTS),
            new FragmentsAction("URL",FragmentsModel.KEY_COMMENTS)
        };
        class InnerCDM extends ColumnDataModel
        {
        	private String _key;
        	private String _name;
        	public InnerCDM(String key, String name )
        	{
        		this._key = key;
        		this._name = name;
        	}
            public Object getValue(Object key) {
            	if (_model == null) return null;
            	if (key instanceof ConversationID)
            	{
            		String[] value = _model.getConversationFragmentKeys((ConversationID) key, _key);
            		return Boolean.valueOf(value != null && value.length > 0);
            	}else // if key instanceof HttpUrl
            	{
                    String[] keys = _model.getUrlFragmentKeys((HttpUrl) key, _key);
                    return Boolean.valueOf(keys != null && keys.length > 0);
            	}
            }
            public String getColumnName() { return _name; }
            public Class<Boolean> getColumnClass() { return Boolean.class; }
        }

		_conversationColumns.put(FragmentsModel.KEY_COMMENTS, new InnerCDM(
				FragmentsModel.KEY_COMMENTS, "Comments"));
		_urlColumns.put(FragmentsModel.KEY_COMMENTS, new InnerCDM(
				FragmentsModel.KEY_COMMENTS, "Comments"));
		_conversationColumns.put(FragmentsModel.KEY_SCRIPTS, new InnerCDM(
				FragmentsModel.KEY_SCRIPTS, "Scripts"));
		_urlColumns.put(FragmentsModel.KEY_SCRIPTS, new InnerCDM(
				FragmentsModel.KEY_SCRIPTS, "Scripts"));
		_conversationColumns.put(FragmentsModel.KEY_FILEUPLOAD, new InnerCDM(
				FragmentsModel.KEY_FILEUPLOAD, "File upload"));
		_urlColumns.put(FragmentsModel.KEY_FILEUPLOAD, new InnerCDM(
				FragmentsModel.KEY_FILEUPLOAD, "File upload"));
		_conversationColumns.put(FragmentsModel.KEY_DOMXSS, new InnerCDM(
				FragmentsModel.KEY_DOMXSS, "DomXss"));
		_urlColumns.put(FragmentsModel.KEY_DOMXSS, new InnerCDM(
				FragmentsModel.KEY_DOMXSS, "DomXss"));
		_conversationColumns.put(FragmentsModel.KEY_FORMS, new InnerCDM(
				FragmentsModel.KEY_FORMS, "Forms"));
		_urlColumns.put(FragmentsModel.KEY_FORMS, new InnerCDM(
				FragmentsModel.KEY_FORMS, "Forms"));
		_conversationColumns.put(FragmentsModel.KEY_HIDDENFIELD, new InnerCDM(
				FragmentsModel.KEY_HIDDENFIELD, "Hidden fields"));
		_urlColumns.put(FragmentsModel.KEY_HIDDENFIELD, new InnerCDM(
				FragmentsModel.KEY_HIDDENFIELD, "Hidden fields"));
	}
    
    /**
	 * This method is called from within the constructor to initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is always
	 * regenerated by the Form Editor.
	 */
    private void initComponents() {//GEN-BEGIN:initComponents
        jSplitPane1 = new javax.swing.JSplitPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        fragmentList = new javax.swing.JList();
        typeComboBox = new javax.swing.JComboBox();
        jScrollPane2 = new javax.swing.JScrollPane();
        conversationTable = new javax.swing.JTable();

        setLayout(new java.awt.BorderLayout());

        setPreferredSize(new java.awt.Dimension(602, 570));
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane1.setResizeWeight(0.65);
        jSplitPane1.setOneTouchExpandable(true);
        jPanel1.setLayout(new java.awt.BorderLayout());

        jPanel1.setMinimumSize(new java.awt.Dimension(400, 300));
        jPanel1.setPreferredSize(new java.awt.Dimension(400, 300));
        jScrollPane1.setViewportView(fragmentList);

        jPanel1.add(jScrollPane1, java.awt.BorderLayout.CENTER);

        jPanel1.add(typeComboBox, java.awt.BorderLayout.NORTH);

        jSplitPane1.setLeftComponent(jPanel1);

        jScrollPane2.setPreferredSize(new java.awt.Dimension(200, 200));
        conversationTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        conversationTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        jScrollPane2.setViewportView(conversationTable);

        jSplitPane1.setRightComponent(jScrollPane2);

        add(jSplitPane1, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    public Action[] getConversationActions() {
        return _conversationActions;
    }
    
    public JPanel getPanel() {
        return this;
    }
    
    public String getPluginName() {
        return "Fragments";
    }
    
    public Action[] getUrlActions() {
        return _urlActions;
    }
    
    public ColumnDataModel[] getConversationColumns() {
        return (ColumnDataModel[]) _conversationColumns.values().toArray(CDM);
    }
    
    public ColumnDataModel[] getUrlColumns() {
        return (ColumnDataModel[]) _urlColumns.values().toArray(CDM);
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTable conversationTable;
    private javax.swing.JList fragmentList;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JComboBox typeComboBox;
    // End of variables declaration//GEN-END:variables
    
    private class FragmentsAction extends AbstractAction {
        
        /**
		 * 
		 */
		private static final long serialVersionUID = -4183487246345191629L;
		private String _type;
        private String _where;
        
        public FragmentsAction(String where, String type) {
            _where = where;
            _type = type;
            putValue(NAME, "Show " + _type.toLowerCase());
            putValue(SHORT_DESCRIPTION, "Displays any " + _type.toLowerCase() + " seen in the " + _where.toLowerCase());
            putValue(_where, null);
        }
        
        private String[] getFragments() {
            String[] fragments = new String[0];
            Object o = getValue(_where);
            if (_where.equals("URL") && o instanceof HttpUrl) {
                HttpUrl url = (HttpUrl) o;
                fragments = _model.getUrlFragmentKeys(url, _type);
            } else if (_where.equals("CONVERSATION") && o instanceof ConversationID) {
                ConversationID id = (ConversationID) o;
                fragments = _model.getConversationFragmentKeys(id, _type);
            }
            // translate fragment keys into actual fragments
            for (int i=0; i<fragments.length; i++) {
                fragments[i] = _model.getFragment(fragments[i]);
            }
            return fragments;
        }
        
        public void actionPerformed(java.awt.event.ActionEvent e) {
            String[] fragments = getFragments();
            if (fragments.length > 0) {
                FragmentsFrame ff = new FragmentsFrame();
                ff.setFragments(fragments);
                ff.setTitle(_type + " in " + _where + " " + getValue(_where));
                ff.setVisible(true);
            }
        }
        
        public void putValue(String key, Object value) {
            super.putValue(key, value);
            if (key != null && key.equals(_where)) {
                if (value != null && getFragments().length > 0) {
                    setEnabled(true);
                } else {
                    setEnabled(false);
                }
            }
        }
        
    }
    
    private class Listener implements FragmentListener {
        
        public void fragmentAdded(final HttpUrl url, final ConversationID id, final String type, String key) {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        ColumnDataModel cdm = _urlColumns.get(type);
                        if (cdm != null) cdm.fireValueChanged(url);
                        cdm = _conversationColumns.get(type);
                        if (cdm != null) cdm.fireValueChanged(id);
                    }
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        public void fragmentAdded(String type, String key, int position) {
        }
        
        public void fragmentsChanged() {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        _flm.fireContentsChanged();
                    }
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
    }
    
    private class FragmentListModel extends AbstractListModel implements FragmentListener {
        
        /**
		 * 
		 */
		private static final long serialVersionUID = -2253303710061129296L;
		private String _type = null;
        private int _size = 0;
        
        public FragmentListModel() {
        }
        
        public void setFilter(Object id, String type) {
            fireIntervalRemoved(this, 0, getSize());
            _type = type;
            fireIntervalAdded(this, 0, getSize());
        }
        
        public Object getElementAt(int index) {
            return _model.getFragmentKeyAt(_type, index);
        }
        
        public int getSize() {
            if (_type == null) return 0;
            _size = _model.getFragmentCount(_type);
            return _size;
        }
        
        protected void fireContentsChanged() {
            if (_size > 0) fireIntervalRemoved(this, 0, _size);
            if (getSize()>0) fireIntervalAdded(this, 0, getSize());
        }
        
        public void fragmentAdded(HttpUrl url, ConversationID id, String type, String key) {}
        
        public void fragmentAdded(String type, String key, final int position) {
            if (_type == null || !_type.equals(type)) return;
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        fireIntervalAdded(this, position, position);
                    }
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        public void fragmentsChanged() {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        fireContentsChanged();
                    }
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
    }
    
    private class FragmentRenderer extends MultiLineCellRenderer {
        
        /**
		 * 
		 */
		private static final long serialVersionUID = -6061481472856144741L;

		public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
            if (value instanceof String) {
                value = _model.getFragment((String) value);
            }
            return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
        }
        
    }
    
    private class FragmentsListListener implements ListSelectionListener {
        
        public void valueChanged(ListSelectionEvent e) {
            if (e.getValueIsAdjusting()) return;
            if (_type == null) return;
            int selected = fragmentList.getSelectedIndex();
            String key = null;
            if (selected > -1)
                key = (String) _flm.getElementAt(selected);
            _model.setSelectedFragment(_type, key);
        }
    }
    
}
