from flask import Blueprint, render_template, request, redirect, url_for, flash
from auth import admin_required

# Define breadcrumb mapping
BREADCRUMBS_MAP = {
    'admin.choice': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'}
    ],
    'admin.dashboard': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Dashboard', 'endpoint': 'admin.dashboard'}
    ],
    'admin.manage_policies': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'}
    ],
    'admin.create_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'},
        {'text': 'Create Policy', 'endpoint': 'admin.create_policy'}
    ],
    'admin.edit_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'},
        {'text': 'Edit Policy', 'endpoint': 'admin.edit_policy'}
    ],
    'admin.delete_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'},
        {'text': 'Delete Policy', 'endpoint': 'admin.delete_policy'}
    ],
    'admin.manage_assignments': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Assignments', 'endpoint': 'admin.manage_assignments'}
    ],
    'admin.create_assignment': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Assignments', 'endpoint': 'admin.manage_assignments'},
        {'text': 'Create Assignment', 'endpoint': 'admin.create_assignment'}
    ],
    'admin.delete_assignment': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Assignments', 'endpoint': 'admin.manage_assignments'},
        {'text': 'Delete Assignment', 'endpoint': 'admin.delete_assignment'}
    ],
    'admin.manage_users': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Users', 'endpoint': 'admin.manage_users'}
    ],
    'admin.promote_user': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Users', 'endpoint': 'admin.manage_users'},
        {'text': 'Promote User', 'endpoint': 'admin.promote_user'}
    ],
    'admin.demote_user': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Users', 'endpoint': 'admin.manage_users'},
        {'text': 'Demote User', 'endpoint': 'admin.demote_user'}
    ],
}

def get_breadcrumbs_for_current_page():
    endpoint = request.endpoint
    breadcrumbs_data = BREADCRUMBS_MAP.get(endpoint, [])
    
    # Convert endpoint names to URLs
    formatted_breadcrumbs = []
    for item in breadcrumbs_data:
        formatted_breadcrumbs.append({
            'text': item['text'],
            'url': url_for(item['endpoint'])
        })
    return formatted_breadcrumbs
from db import (
    create_policy as write_create_policy, 
    get_policies as read_get_policies, 
    edit_policy as write_edit_policy, 
    get_policy as read_get_policy, 
    delete_policy as write_delete_policy, 
    create_assignment as write_create_assignment, 
    get_pending_assignments as read_get_pending_assignments, 
    delete_assignment as write_delete_assignment, 
    get_users as read_get_users, 
    promote_user_to_admin as write_promote_user_to_admin, 
    demote_user_from_admin as write_demote_user_from_admin,
    get_policies_with_assignment_count
)
from time import time

admin = Blueprint('admin', __name__, url_prefix='/admin')

def _process_user_selection(request, action_func, success_msg, failure_msg):
    selected_users = request.form.getlist('users')
    
    all_users_result = read_get_users()
    if all_users_result['status'] != '200':
        flash('Could not retrieve user data.', 'error')
        return redirect(url_for('admin.manage_users'))
        
    all_users = {user['uuid']: user for user in all_users_result['data']}
    
    if action_func == write_demote_user_from_admin:
        admin_count = sum(1 for u in all_users.values() if u['is_admin'])
        if len(selected_users) >= admin_count:
            flash('Cannot demote all administrators. At least one must remain.', 'error')
            return redirect(url_for('admin.manage_users'))

    successful_actions = 0
    failed_actions = []

    for user_uuid in selected_users:
        result = action_func(user_uuid)
        if result['status'] == '200':
            successful_actions += 1
        else:
            user_name = all_users.get(user_uuid, {}).get('name', 'Unknown User')
            failed_actions.append({
                'user_name': user_name,
                'error': result['message']
            })

    if successful_actions > 0:
        flash(success_msg.format(count=successful_actions, s='s' if successful_actions != 1 else ''), 'success')
    
    for failure in failed_actions:
        flash(failure_msg.format(user_name=failure['user_name'], error=failure['error']), 'error')
        
    return redirect(url_for('admin.manage_users'))

@admin.route('/choice', methods=['GET'])
@admin_required
def choice():
    return render_template('admin/choice.html')

@admin.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    return render_template('admin/dashboard.html')

@admin.route('/manage_policies', methods=['GET'])
@admin_required
def manage_policies():
    policies = read_get_policies()
    return render_template('admin/manage_policies/hub.html', policies=policies["data"])

@admin.route('/manage_policies/create', methods=['GET', 'POST'])
@admin_required
def create_policy():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        pdf_link = request.form['pdf_link']
        write_create_policy(name, description, pdf_link)
        return redirect(url_for('admin.manage_policies'))
    return render_template('admin/manage_policies/create.html')

@admin.route('/manage_policies/edit', methods=['GET', 'POST'])
@admin_required
def edit_policy():
    if request.method == 'POST':
        policy_uuid = request.form['policy']
        original_policy = read_get_policy(uuid=policy_uuid)["data"]
        name = request.form['name'] if request.form['name'] else original_policy["name"]
        description = request.form['description'] if request.form['description'] else original_policy["description"]
        pdf_link = request.form['pdf_link'] if request.form['pdf_link'] else original_policy["pdf_link"]
        write_edit_policy(policy_uuid, name, description, pdf_link)
        return redirect(url_for('admin.manage_policies'))
    policies = read_get_policies()
    return render_template('admin/manage_policies/edit.html', policies=policies["data"])
    
@admin.route('/manage_policies/delete', methods=['GET', 'POST'])
@admin_required
def delete_policy():
    if request.method == 'POST':
        selected_policies = request.form.getlist('policies')
        
        successful_deletions = 0
        failed_deletions = []
        total_assignments_deleted = 0
        
        policies_with_counts = get_policies_with_assignment_count()['data']
        policy_map = {p['uuid']: p for p in policies_with_counts}
        
        for policy_uuid in selected_policies:
            if policy_uuid in policy_map:
                total_assignments_deleted += policy_map[policy_uuid].get('assignment_count', 0)
            
            result = write_delete_policy(policy_uuid)
            if result['status'] == '200':
                successful_deletions += 1
            else:
                policy_name = policy_map.get(policy_uuid, {}).get('name', 'Unknown Policy')
                failed_deletions.append({
                    'policy_name': policy_name,
                    'error': result['message']
                })
        
        if successful_deletions > 0:
            message = f'Successfully deleted {successful_deletions} polic{"ies" if successful_deletions != 1 else "y"}'
            if total_assignments_deleted > 0:
                message += f' and {total_assignments_deleted} associated assignment{"s" if total_assignments_deleted != 1 else ""}'
            message += '!'
            flash(message, 'success')
        
        if failed_deletions:
            for failure in failed_deletions:
                flash(f'Failed to delete policy "{failure["policy_name"]}": {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_policies'))
    
    policies_result = get_policies_with_assignment_count()
    policies = policies_result['data'] if policies_result['status'] == '200' else []
    
    return render_template('admin/manage_policies/delete.html', policies=policies)

@admin.route('/manage_assignments', methods=['GET'])
@admin_required
def manage_assignments():
    assignments = read_get_pending_assignments()
    return render_template('admin/manage_assignments/hub.html', 
                         assignments=assignments["data"],
                         now=int(time()))

@admin.route('/manage_assignments/delete', methods=['GET', 'POST'])
@admin_required
def delete_assignment():
    if request.method == 'POST':
        selected_assignments = request.form.getlist('assignments')
        
        successful_deletions = 0
        failed_deletions = []
        
        for assignment_uuid in selected_assignments:
            result = write_delete_assignment(assignment_uuid)
            if result['status'] == '200':
                successful_deletions += 1
            else:
                failed_deletions.append({
                    'assignment_uuid': assignment_uuid,
                    'error': result['message']
                })
        
        if successful_deletions > 0:
            flash(f'Successfully deleted {successful_deletions} assignment{"s" if successful_deletions != 1 else ""}!', 'success')
        
        if failed_deletions:
            for failure in failed_deletions:
                flash(f'Failed to delete assignment: {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_assignments'))
    
    assignments = read_get_pending_assignments()
    return render_template('admin/manage_assignments/delete.html', assignments=assignments["data"])

@admin.route('/manage_assignments/create', methods=['GET', 'POST'])
@admin_required
def create_assignment():
    if request.method == 'POST':
        selected_users = request.form.getlist('users')
        policy_uuid = request.form['policy']
        timeframe_days = int(request.form['timeframe_days'])
        
        successful_assignments = 0
        failed_assignments = []
        
        for user_uuid in selected_users:
            result = write_create_assignment(user_uuid, policy_uuid, timeframe_days)
            if result['status'] == '201':
                successful_assignments += 1
            else:
                user_info = get_user(uuid=user_uuid)
                user_name = user_info['data']['name'] if user_info['status'] == '200' else 'Unknown User'
                failed_assignments.append({
                    'user_name': user_name,
                    'error': result['message']
                })
        
        if successful_assignments > 0:
            flash(f'Successfully created {successful_assignments} assignment{"s" if successful_assignments != 1 else ""}!', 'success')
        
        if failed_assignments:
            for failure in failed_assignments:
                flash(f'Failed to create assignment for {failure["user_name"]}: {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_assignments'))
    
    users = read_get_users()
    policies = read_get_policies()
    return render_template('admin/manage_assignments/create.html', 
                         users=users["data"], 
                         policies=policies["data"])

@admin.route('/manage_users', methods=['GET'])
@admin_required
def manage_users():
    return render_template('admin/manage_users/hub.html')

@admin.route('/manage_users/promote', methods=['GET', 'POST'])
@admin_required
def promote_user():
    if request.method == 'POST':
        return _process_user_selection(
            request,
            write_promote_user_to_admin,
            'Successfully promoted {count} user{s} to administrator!',
            'Failed to promote {user_name}: {error}'
        )
    
    users_result = read_get_users()
    users = [user for user in users_result["data"] if not user['is_admin']] if users_result["status"] == "200" else []
    return render_template('admin/manage_users/promote.html', users=users)

@admin.route('/manage_users/demote', methods=['GET', 'POST'])
@admin_required
def demote_user():
    if request.method == 'POST':
        return _process_user_selection(
            request,
            write_demote_user_from_admin,
            'Successfully demoted {count} administrator{s} to regular user!',
            'Failed to demote {user_name}: {error}'
        )
    
    users_result = read_get_users()
    users = [user for user in users_result["data"] if user['is_admin']] if users_result["status"] == "200" else []
    return render_template('admin/manage_users/demote.html', users=users, breadcrumbs=get_breadcrumbs_for_current_page())
