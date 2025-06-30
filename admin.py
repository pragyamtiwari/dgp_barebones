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
    'admin.view_logs_search': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'View Logs', 'endpoint': 'admin.view_logs_search'}
    ],
    'admin.view_user_logs': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'View Logs', 'endpoint': 'admin.view_logs_search'},
        {'text': 'User Logs', 'endpoint': 'admin.view_user_logs'}
    ],
    'admin.manage_tags': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Tags', 'endpoint': 'admin.manage_tags'}
    ],
    'admin.create_tag': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Tags', 'endpoint': 'admin.manage_tags'},
        {'text': 'Create Tag', 'endpoint': 'admin.create_tag'}
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
    get_user as read_get_user,
    promote_user_to_admin as write_promote_user_to_admin, 
    demote_user_from_admin as write_demote_user_from_admin,
    get_policies_with_assignment_count,
    get_all_pending_assignments_with_status,
    get_user_assignment_logs,
    create_tag as write_create_tag,
    get_tags as read_get_tags,
    get_tag as read_get_tag,
    delete_tag as write_delete_tag,
    update_tag_members as write_update_tag_members,
    add_user_to_tag as write_add_user_to_tag,
    remove_user_from_tag as write_remove_user_from_tag,
    get_users_by_tag as read_get_users_by_tag,
    get_tags_with_member_count,
    get_users_with_tags
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
    # Get pending assignments with status
    pending_assignments_result = get_all_pending_assignments_with_status()
    pending_assignments = pending_assignments_result['data'] if pending_assignments_result['status'] == '200' else []
    
    return render_template('admin/dashboard.html', 
                         pending_assignments=pending_assignments,
                         now=int(time()))


@admin.route('/logs', methods=['GET'])
@admin_required
def view_logs_search():
    query = request.args.get('q', '')
    users_result = get_users_with_tags()
    users = users_result['data'] if users_result['status'] == '200' else []

    if query:
        users = [u for u in users if query.lower() in u['name'].lower()]

    return render_template('admin/view_logs_search.html',
                         users=users,
                         query=query)

@admin.route('/user/<user_uuid>/logs', methods=['GET'])
@admin_required
def view_user_logs(user_uuid):
    # Get user info
    user_result = read_get_user(uuid=user_uuid)
    if user_result['status'] != '200':
        flash('User not found.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    # Get user's assignment logs
    logs_result = get_user_assignment_logs(user_uuid)
    logs = logs_result['data'] if logs_result['status'] == '200' else []
    
    return render_template('admin/user_logs.html',
                         user_info=user_result['data'],
                         logs=logs)

@admin.route('/manage_tags', methods=['GET'])
@admin_required
def manage_tags():
    tags_result = get_tags_with_member_count()
    tags = tags_result['data'] if tags_result['status'] == '200' else []
    return render_template('admin/manage_tags/hub.html', tags=tags)

@admin.route('/manage_tags/create', methods=['GET', 'POST'])
@admin_required
def create_tag():
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form.get('description', '').strip()
        
        result = write_create_tag(name, description)
        if result['status'] == '201':
            flash(f'Tag "{name}" created successfully!', 'success')
        else:
            flash(f'Failed to create tag: {result["message"]}', 'error')
        
        return redirect(url_for('admin.manage_tags'))
    
    return render_template('admin/manage_tags/create.html')

@admin.route('/manage_tags/<tag_uuid>/members', methods=['GET', 'POST'])
@admin_required
def manage_tag_members(tag_uuid):
    # Get tag info
    tag_result = read_get_tag(uuid=tag_uuid)
    if tag_result['status'] != '200':
        flash('Tag not found.', 'error')
        return redirect(url_for('admin.manage_tags'))
    
    tag_info = tag_result['data']
    
    if request.method == 'POST':
        # Get current members
        current_members = set(tag_info['members'].split(',')) if tag_info['members'] else set()
        
        # Get selected users
        selected_users = set(request.form.getlist('users'))
        
        # Determine which users to add and remove
        users_to_add = selected_users - current_members
        users_to_remove = current_members - selected_users
        
        # Process additions
        for user_uuid in users_to_add:
            write_add_user_to_tag(tag_uuid, user_uuid)
        
        # Process removals
        for user_uuid in users_to_remove:
            write_remove_user_from_tag(tag_uuid, user_uuid)
        
        flash(f'Tag membership updated successfully!', 'success')
        return redirect(url_for('admin.manage_tags'))
    
    # Get all users with membership status
    all_users_result = read_get_users()
    if all_users_result['status'] != '200':
        flash('Could not retrieve users.', 'error')
        return redirect(url_for('admin.manage_tags'))
    
    current_members = set(tag_info['members'].split(',')) if tag_info['members'] else set()
    
    users = []
    for user in all_users_result['data']:
        user_dict = dict(user)
        user_dict['is_member'] = user['uuid'] in current_members
        users.append(user_dict)
    
    return render_template('admin/manage_tags/manage_members.html',
                         tag_info=tag_info,
                         users=users)

@admin.route('/manage_tags/edit', methods=['GET', 'POST'])
@admin_required
def edit_tag():
    if request.method == 'POST':
        tag_uuid = request.form['tag']
        new_name = request.form.get('name', '').strip()
        new_description = request.form.get('description', '').strip()
        
        # Get current tag data
        tag_result = read_get_tag(uuid=tag_uuid)
        if tag_result['status'] != '200':
            flash('Tag not found.', 'error')
            return redirect(url_for('admin.manage_tags'))
        
        current_tag = tag_result['data']
        
        # Use new values or keep current ones
        final_name = new_name if new_name else current_tag['name']
        final_description = new_description if new_description else current_tag['description']
        
        result = write_update_tag_members(tag_uuid, name=final_name, description=final_description)
        if result['status'] == '200':
            flash('Tag updated successfully!', 'success')
        else:
            flash(f'Failed to update tag: {result["message"]}', 'error')
        
        return redirect(url_for('admin.manage_tags'))
    
    tags_result = get_tags_with_member_count()
    tags = tags_result['data'] if tags_result['status'] == '200' else []
    return render_template('admin/manage_tags/edit.html', tags=tags)

@admin.route('/manage_tags/delete', methods=['GET', 'POST'])
@admin_required
def delete_tag():
    if request.method == 'POST':
        selected_tags = request.form.getlist('tags')
        
        successful_deletions = 0
        failed_deletions = []
        
        for tag_uuid in selected_tags:
            result = write_delete_tag(tag_uuid)
            if result['status'] == '200':
                successful_deletions += 1
            else:
                failed_deletions.append(result['message'])
        
        if successful_deletions > 0:
            flash(f'Successfully deleted {successful_deletions} tag{"s" if successful_deletions != 1 else ""}!', 'success')
        
        for error in failed_deletions:
            flash(f'Failed to delete tag: {error}', 'error')
        
        return redirect(url_for('admin.manage_tags'))
    
    tags_result = get_tags_with_member_count()
    tags = tags_result['data'] if tags_result['status'] == '200' else []
    return render_template('admin/manage_tags/delete.html', tags=tags)

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
                user_info = read_get_user(uuid=user_uuid)
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
    
    # Get users with their tags
    users_result = get_users_with_tags()
    users = users_result['data'] if users_result['status'] == '200' else []
    
    policies = read_get_policies()
    tags = read_get_tags()
    
    return render_template('admin/manage_assignments/create.html', 
                         users=users, 
                         policies=policies["data"],
                         tags=tags["data"])

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